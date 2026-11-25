"""Social module tests. All HTTP is mocked with respx: these never touch the network."""

import httpx
import respx

from osint_agent.modules.social import (
    _check_bluesky,
    _check_github,
    _check_hackernews,
    _check_mastodon,
    _check_reddit,
)

USERNAME = "jdoe"

GITHUB_BODY = {
    "login": "jdoe",
    "html_url": "https://github.com/jdoe",
    "name": "Jane Doe",
    "bio": "Security work. Notes at https://notes.example.test and https://notes.example.test",
    "blog": "jane.example.test",
    "location": "Kuala Lumpur",
    "company": "@acme",
    "public_repos": 12,
    "created_at": "2013-01-01T00:00:00Z",
    "twitter_username": "janedoe",
}


def typed(findings, entity_type):
    return [f for f in findings if f.entity_type == entity_type]


@respx.mock
async def test_github_profile_yields_an_account_and_its_pivots(client, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    respx.get(f"https://api.github.com/users/{USERNAME}").mock(
        return_value=httpx.Response(200, json=GITHUB_BODY)
    )

    findings, errors = await _check_github(USERNAME, client)

    assert errors == []
    account = typed(findings, "account")[0]
    assert account.value == "github.com/jdoe"
    assert account.confidence == 0.6
    assert account.source_url == "https://github.com/jdoe"
    assert account.raw["public_repos"] == 12
    assert account.raw["name"] == "Jane Doe"

    linked_urls = {f.value for f in typed(findings, "linked_url")}
    # A bare host in the blog field gets a scheme so the pivot is usable as a URL.
    assert "https://jane.example.test" in linked_urls
    # The bio mentions the same URL twice; it should appear once.
    assert "https://notes.example.test" in linked_urls
    assert len(typed(findings, "linked_url")) == 2

    twitter = typed(findings, "linked_account")[0]
    assert twitter.value == "twitter.com/janedoe"
    assert twitter.source_url == "https://twitter.com/janedoe"
    assert twitter.confidence == 0.7


@respx.mock
async def test_github_404_is_a_clean_negative(client, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    respx.get(f"https://api.github.com/users/{USERNAME}").mock(return_value=httpx.Response(404))

    assert await _check_github(USERNAME, client) == ([], [])


@respx.mock
async def test_github_rate_limit_suggests_a_token(client, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    respx.get(f"https://api.github.com/users/{USERNAME}").mock(return_value=httpx.Response(403))

    findings, errors = await _check_github(USERNAME, client)

    assert findings == []
    assert "GITHUB_TOKEN" in errors[0]


@respx.mock
async def test_reddit_403_is_an_error_not_a_crash(client):
    respx.get(f"https://www.reddit.com/user/{USERNAME}/about.json").mock(
        return_value=httpx.Response(403)
    )

    findings, errors = await _check_reddit(USERNAME, client)

    assert findings == []
    assert len(errors) == 1
    assert "403" in errors[0]


@respx.mock
async def test_reddit_profile_reports_karma_and_bio_links(client):
    respx.get(f"https://www.reddit.com/user/{USERNAME}/about.json").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "name": "jdoe",
                    "link_karma": 120,
                    "comment_karma": 4300,
                    "total_karma": 4420,
                    "created_utc": 1356998400,
                    "verified": True,
                    "subreddit": {"public_description": "see https://jane.example.test"},
                }
            },
        )
    )

    findings, errors = await _check_reddit(USERNAME, client)

    assert errors == []
    account = typed(findings, "account")[0]
    assert account.value == "reddit.com/user/jdoe"
    assert account.raw["comment_karma"] == 4300
    assert account.raw["created"] == "2013-01-01"
    assert typed(findings, "linked_url")[0].value == "https://jane.example.test"


@respx.mock
async def test_bluesky_unknown_handle_is_a_clean_negative(client):
    respx.get(url__startswith="https://public.api.bsky.app").mock(
        return_value=httpx.Response(400, json={"error": "InvalidRequest"})
    )

    assert await _check_bluesky(USERNAME, client) == ([], [])


@respx.mock
async def test_bluesky_profile_reports_followers(client):
    route = respx.get(url__startswith="https://public.api.bsky.app").mock(
        return_value=httpx.Response(
            200,
            json={
                "did": "did:plc:abc123",
                "handle": "jdoe.bsky.social",
                "displayName": "Jane Doe",
                "description": "Notes at https://jane.example.test",
                "followersCount": 42,
                "followsCount": 7,
                "postsCount": 300,
                "createdAt": "2023-05-01T00:00:00Z",
            },
        )
    )

    findings, errors = await _check_bluesky(USERNAME, client)

    assert errors == []
    # A bare username is qualified with the default bsky.social domain.
    assert route.calls[0].request.url.params["actor"] == "jdoe.bsky.social"
    account = typed(findings, "account")[0]
    assert account.value == "bsky.app/profile/jdoe.bsky.social"
    assert account.raw["followers"] == 42
    assert typed(findings, "linked_url")[0].value == "https://jane.example.test"


@respx.mock
async def test_hackernews_about_is_stripped_of_markup(client):
    respx.get(f"https://hn.algolia.com/api/v1/users/{USERNAME}").mock(
        return_value=httpx.Response(
            200,
            json={
                "username": "jdoe",
                "karma": 1234,
                "created_at": "2011-02-03T00:00:00.000Z",
                "about": "Engineer &amp; tinkerer.<p>Site: <a "
                'href="https://jane.example.test">jane.example.test</a>',
            },
        )
    )

    findings, errors = await _check_hackernews(USERNAME, client)

    assert errors == []
    account = typed(findings, "account")[0]
    assert account.raw["karma"] == 1234
    assert account.raw["about"] == "Engineer & tinkerer. Site: jane.example.test"
    assert typed(findings, "linked_url")[0].value == "https://jane.example.test"


@respx.mock
async def test_hackernews_unknown_user_answers_200_with_no_username(client):
    respx.get(f"https://hn.algolia.com/api/v1/users/{USERNAME}").mock(
        return_value=httpx.Response(200, json={"error": "Not found"})
    )

    assert await _check_hackernews(USERNAME, client) == ([], [])


@respx.mock
async def test_hackernews_500_means_no_such_user(client):
    """Algolia really does answer 500 for an unknown username, verified against a live user."""
    respx.get(f"https://hn.algolia.com/api/v1/users/{USERNAME}").mock(
        return_value=httpx.Response(500, text="<title>500 Internal Server Error</title>")
    )

    assert await _check_hackernews(USERNAME, client) == ([], [])


@respx.mock
async def test_mastodon_is_skipped_silently_for_a_plain_username(client):
    # No respx routes are registered, so any HTTP call here would fail the test outright.
    assert await _check_mastodon(USERNAME, client) == ([], [])
    assert await _check_mastodon("jdoe@not a host", client) == ([], [])
    assert await _check_mastodon("@jdoe@a@b", client) == ([], [])


@respx.mock
async def test_mastodon_webfinger_resolves_a_full_handle(client):
    respx.get(url__startswith="https://mastodon.example/.well-known/webfinger").mock(
        return_value=httpx.Response(
            200,
            json={
                "subject": "acct:jdoe@mastodon.example",
                "aliases": ["https://mastodon.example/@jdoe"],
                "links": [
                    {
                        "rel": "http://webfinger.net/rel/profile-page",
                        "type": "text/html",
                        "href": "https://mastodon.example/@jdoe",
                    }
                ],
            },
        )
    )

    findings, errors = await _check_mastodon("jdoe@mastodon.example", client)

    assert errors == []
    assert findings[0].value == "jdoe@mastodon.example"
    assert findings[0].source_url == "https://mastodon.example/@jdoe"
    assert findings[0].raw["instance"] == "mastodon.example"

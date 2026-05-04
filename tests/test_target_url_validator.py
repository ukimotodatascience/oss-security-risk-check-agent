import pytest

from src.targets.url_validator import parse_github_repo_url


def test_parse_github_repo_url_accepts_https_github_url():
    repo = parse_github_repo_url("https://github.com/owner/repo")

    assert repo.owner == "owner"
    assert repo.repo == "repo"


def test_parse_github_repo_url_strips_dot_git_suffix():
    repo = parse_github_repo_url("https://github.com/owner/repo.git")

    assert repo.owner == "owner"
    assert repo.repo == "repo"


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/owner/repo",
        "file:///etc/passwd",
        "ssh://git@github.com/owner/repo",
        "git://github.com/owner/repo",
        "https://localhost/owner/repo",
        "https://127.0.0.1/owner/repo",
        "https://example.com/owner/repo",
        "https://token@github.com/owner/repo",
        "https://github.com:8443/owner/repo",
    ],
)
def test_parse_github_repo_url_rejects_unsafe_or_unsupported_urls(url):
    with pytest.raises(ValueError):
        parse_github_repo_url(url)

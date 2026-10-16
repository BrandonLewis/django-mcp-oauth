"""Authorization gates used by tests through MCP_OAUTH_AUTHORIZE_USER."""


def deny_all(user) -> bool:
    return False


def staff_only(user) -> bool:
    return bool(user.is_staff)

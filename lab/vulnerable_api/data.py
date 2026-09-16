from lab.vulnerable_api.models import AccountSettings, Order, SyntheticUser

USERS: dict[str, SyntheticUser] = {
    "alice": SyntheticUser(
        id=1,
        username="alice",
        role="user",
        owned_resources=(101, 102),
        synthetic_email="alice@example.invalid",
        internal_account_id="acct-lab-0001",
    ),
    "bob": SyntheticUser(
        id=2,
        username="bob",
        role="user",
        owned_resources=(201, 202),
        synthetic_email="bob@example.invalid",
        internal_account_id="acct-lab-0002",
    ),
    "admin": SyntheticUser(
        id=99,
        username="admin",
        role="admin",
        owned_resources=(),
        synthetic_email="admin@example.invalid",
        internal_account_id="acct-lab-0099",
    ),
}

TOKENS: dict[str, str] = {
    "alice-token": "alice",
    "bob-token": "bob",
    "admin-token": "admin",
}

ORDERS: dict[int, Order] = {
    101: Order(id=101, owner="alice", item="synthetic-book", amount=25, status="paid"),
    102: Order(id=102, owner="alice", item="synthetic-lamp", amount=40, status="shipped"),
    201: Order(id=201, owner="bob", item="synthetic-chair", amount=75, status="paid"),
    202: Order(id=202, owner="bob", item="synthetic-desk", amount=120, status="processing"),
}

SETTINGS: dict[str, AccountSettings] = {
    "alice": AccountSettings(username="alice", locale="en-GB", notifications_enabled=True),
    "bob": AccountSettings(username="bob", locale="de-DE", notifications_enabled=False),
    "admin": AccountSettings(username="admin", locale="en-US", notifications_enabled=True),
}

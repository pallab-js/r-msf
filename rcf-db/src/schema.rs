//! Diesel schema definitions.

diesel::table! {
    hosts (id) {
        id -> Text,
        address -> Text,
        mac_address -> Nullable<Text>,
        os -> Nullable<Text>,
        os_accuracy -> Nullable<Text>,
        state -> Text,
        first_seen -> BigInt,
        last_seen -> BigInt,
        notes -> Nullable<Text>,
    }
}

diesel::table! {
    services (id) {
        id -> Text,
        host_id -> Text,
        port -> Integer,
        protocol -> Text,
        state -> Text,
        name -> Nullable<Text>,
        product -> Nullable<Text>,
        version -> Nullable<Text>,
        extra_info -> Nullable<Text>,
        banner -> Nullable<Text>,
        discovered_at -> BigInt,
    }
}

diesel::table! {
    credentials (id) {
        id -> Text,
        host_id -> Text,
        port -> Integer,
        service -> Text,
        username -> Text,
        password -> Text,
        password_type -> Text,
        source -> Text,
        created_at -> BigInt,
    }
}

diesel::table! {
    vulnerabilities (id) {
        id -> Text,
        host_id -> Text,
        port -> Nullable<Integer>,
        service -> Text,
        name -> Text,
        cve -> Nullable<Text>,
        severity -> Text,
        proof -> Nullable<Text>,
        #[sql_name = "references"]
        references_col -> Nullable<Text>,
        discovered_at -> BigInt,
    }
}

diesel::table! {
    sessions (id) {
        id -> Integer,
        session_uuid -> Text,
        host_id -> Text,
        type_ -> Text,
        tunnel_local -> Nullable<Text>,
        tunnel_remote -> Nullable<Text>,
        via_payload -> Nullable<Text>,
        started_at -> BigInt,
        last_seen -> BigInt,
        info -> Nullable<Text>,
    }
}

diesel::table! {
    loot (id) {
        id -> Text,
        host_id -> Text,
        ltype -> Text,
        path -> Text,
        content -> Nullable<Text>,
        info -> Nullable<Text>,
        created_at -> BigInt,
    }
}

diesel::joinable!(services -> hosts (host_id));
diesel::joinable!(credentials -> hosts (host_id));
diesel::joinable!(vulnerabilities -> hosts (host_id));
diesel::joinable!(sessions -> hosts (host_id));
diesel::joinable!(loot -> hosts (host_id));

diesel::allow_tables_to_appear_in_same_query!(
    hosts,
    services,
    credentials,
    vulnerabilities,
    sessions,
    loot,
);

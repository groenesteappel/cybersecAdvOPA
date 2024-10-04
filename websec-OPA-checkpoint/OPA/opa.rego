package barmanagement

import future.keywords

default allow := false

allow if user_is_bartender

allow if {
    user_is_customer
    action_is_order_drink
    allowed_to_order_drink
}

user_is_bartender if "bartender" in claims.role
user_is_customer if "customer" in claims.role
user_is_legal_age if to_number(claims.age) >= 16
action_is_order_drink if input.request.path == "/api/bar"
action_is_add_drink if input.request.path == "/api/managebar"

allowed_to_order_drink if {
    user_is_legal_age
} else if {
    not user_is_legal_age
    input.request.body.DrinkName == "Fristi"
}

claims := payload if {
    [_, payload, _] := io.jwt.decode(bearer_token)
}

bearer_token := t if {
    v := input.request.headers.Authorization
    startswith(v, "Bearer ")
    t := substring(v, count("Bearer "), -1)
}

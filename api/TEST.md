```bash
# create user
curl -s http://localhost:3000/v0.1-beta/signup \
    -X GET \
    | jq .

# Get current user info
export BEARER_TOKEN=
curl -s http://localhost:3000/v0.1-beta/user \
    -X GET \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    | jq .

# Update current user info
export BEARER_TOKEN=
export USERNAME=
curl -s http://localhost:3000/v0.1-beta/user \
    -X PUT \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    -H 'Content-type: application/json' \
    -d '{"username":"'$USERNAME'"}' \
    | jq .

# Get config
export BEARER_TOKEN=
curl -s http://localhost:3000/v0.1-beta/user/config \
    -X GET \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    | jq .

# Update config
export BEARER_TOKEN=
export PUBLIC_KEY=
export ENDPOINT=
curl -s http://localhost:3000/v0.1-beta/user/config \
    -X POST \
    -H "Authorization: Bearer ${BEARER_TOKEN}" \
    -H 'Content-type: application/json' \
    -d '{"public_key":"'${PUBLIC_KEY}'","endpoint":"'${ENDPOINT}'"}' \
    | jq .
```

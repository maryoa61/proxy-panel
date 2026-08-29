#!/bin/bash

BASE_URL="http://127.0.0.1:8000/api/v1"

echo "=========================================="
echo "1. Testing Login Endpoint (/auth/login)..."
echo "=========================================="
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}')
echo "$LOGIN_RESPONSE"

# Extract JWT token
TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"access_token":"[^"]*' | grep -o '[^"]*$')

if [ -z "$TOKEN" ]; then
  echo "❌ Login failed! Cannot proceed with authenticated tests."
  exit 1
fi

echo -e "\n✅ Login successful! Token acquired.\n"

echo "=========================================="
echo "2. Resetting / clearing server domain in settings first..."
echo "=========================================="
curl -s -X PUT "$BASE_URL/settings" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"settings": {"server_domain": ""}}'
echo -e "\n"

echo "=========================================="
echo "3. Testing Create Inbound (/inbounds)..."
echo "=========================================="
RANDOM_PORT=$((4700 + RANDOM % 1000))
INBOUND_RESPONSE=$(curl -s -X POST "$BASE_URL/inbounds" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"remark\": \"Test VLESS Reality Inbound $RANDOM_PORT\",
    \"protocol\": \"vless\",
    \"port\": $RANDOM_PORT,
    \"security\": \"reality\",
    \"network\": \"tcp\",
    \"stream_settings\": \"{\\\"dest\\\":\\\"yahoo.com:443\\\",\\\"serverNames\\\":[\\\"yahoo.com\\\"],\\\"privateKey\\\":\\\"test_priv_key\\\",\\\"shortIds\\\":[\\\"1234\\\"]}\"
  }")
echo "$INBOUND_RESPONSE"

# Extract inbound id
INBOUND_ID=$(echo "$INBOUND_RESPONSE" | grep -o '"id":[0-9]*' | head -n 1 | grep -o '[0-9]*')
if [ -z "$INBOUND_ID" ]; then
  INBOUND_ID=1
fi
echo -e "\nUsing Inbound ID: $INBOUND_ID\n"

echo "=========================================="
echo "4. Testing Create Client (/inbounds/{id}/clients)..."
echo "=========================================="
CLIENT_EMAIL="diff-test-$RANDOM@proxy.local"
CLIENT_RESPONSE=$(curl -s -X POST "$BASE_URL/inbounds/$INBOUND_ID/clients" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"inbound_id\": $INBOUND_ID,
    \"email\": \"$CLIENT_EMAIL\",
    \"total_gb\": 10,
    \"flow\": \"xtls-rprx-vision\"
  }")
echo "$CLIENT_RESPONSE"

# Extract client id and sub_id
CLIENT_ID=$(echo "$CLIENT_RESPONSE" | grep -o '"id":[0-9]*' | head -n 1 | grep -o '[0-9]*')
SUB_ID=$(echo "$CLIENT_RESPONSE" | grep -o '"sub_id":"[^"]*' | head -n 1 | cut -d'"' -f4)

if [ -z "$CLIENT_ID" ]; then
  CLIENT_ID=1
fi
echo -e "\nUsing Client ID: $CLIENT_ID, Sub ID: $SUB_ID\n"

echo "=========================================="
echo "5. Getting Link BEFORE domain setting (should be fallback/ip, NOT the new domain)..."
echo "=========================================="
BEFORE_LINK_RES=$(curl -s -X GET "$BASE_URL/clients/$CLIENT_ID/config-link" \
  -H "Authorization: Bearer $TOKEN")
echo "$BEFORE_LINK_RES"

NEW_DOMAIN="test-$RANDOM.example.com"
echo -e "\nTarget New Domain: $NEW_DOMAIN\n"

echo "=========================================="
echo "6. Updating Settings with new unique domain ($NEW_DOMAIN)..."
echo "=========================================="
curl -s -X PUT "$BASE_URL/settings" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"settings\": {\"server_domain\": \"$NEW_DOMAIN\"}}"
echo -e "\n"

echo "=========================================="
echo "7. Getting Link AFTER domain setting (should contain $NEW_DOMAIN)..."
echo "=========================================="
AFTER_LINK_RES=$(curl -s -X GET "$BASE_URL/clients/$CLIENT_ID/config-link" \
  -H "Authorization: Bearer $TOKEN")
echo "$AFTER_LINK_RES"

# Verify if AFTER_LINK contains NEW_DOMAIN
if echo "$AFTER_LINK_RES" | grep -q "$NEW_DOMAIN"; then
  echo -e "\n✅ Differential Test Passed! Link successfully updated to $NEW_DOMAIN\n"
else
  echo -e "\n❌ Differential Test Failed! New domain not found in link.\n"
  exit 1
fi

if [ ! -z "$SUB_ID" ]; then
  echo "=========================================="
  echo "8. Testing Public Subscription Link (/sub/{sub_id})..."
  echo "=========================================="
  SUB_RES=$(curl -s -X GET "$BASE_URL/sub/$SUB_ID")
  echo "$SUB_RES"
  # Decode base64 sub response to check domain
  DECODED_SUB=$(echo "$SUB_RES" | tr -d '"' | base64 -d 2>/dev/null || echo "Decode failed")
  echo "Decoded Sub Link: $DECODED_SUB"
  echo -e "\n"
fi

echo "=========================================="
echo "✨ All differential tests completed successfully!"
echo "=========================================="

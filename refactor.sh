#!/bin/bash

# Input parameters
CLUSTER=908
NAMESPACE="nuobject2sh-dev"
DEPLOYMENT_COUNT=4
REFACTOR_IMAGE="hub.tess.io/yawzhang/storage_mgr:refactor_new-RelWithDebInfo"
NEW_IMAGE="hub.tess.io/yawzhang/storage_mgr:crc_1027-RelWithDebInfo"

# Function to check deployment status
check_deployment_status() {
  local deployment=$1
  local status
  status=$(tess kubectl --context="$CLUSTER" -n "$NAMESPACE" get deployment "$deployment" -o jsonpath='{.status.readyReplicas}' 2>/dev/null)
  if [[ "$status" -eq 1 ]]; then
    return 0
  else
    return 1
  fi
}

# Function to check pod logs
check_pod_logs() {
  local pod=$1
  local log_message=$2
  tess kubectl --context="$CLUSTER" -n "$NAMESPACE" logs "$pod" | grep -q "$log_message"
  return $?
}

start_idx=1
for i in $(seq "$start_idx" "$DEPLOYMENT_COUNT"); do
  DEPLOYMENT="sm-long-running$i-1007"
  POD=$(tess kubectl --context="$CLUSTER" -n "$NAMESPACE" get pods -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep "$DEPLOYMENT")
  echo "Processing deployment $DEPLOYMENT pod $POD..."

  # PRE-CHECK
  CURRENT_IMAGE=$(tess kubectl --context="$CLUSTER" -n "$NAMESPACE" get pod "$POD" -o jsonpath='{.spec.containers[?(@.name=="sm-app")].image}')
  if [[ "$CURRENT_IMAGE" == "$NEW_IMAGE" ]]; then
    echo "[PRE-CHECK] Pod $POD is already using the new image $NEW_IMAGE. Skipping..."
    continue
  fi

  # Step 1: Update deployment strategy to Recreate and set sm-app image to refactor image
  echo "[Step 1]. Updating deployment $DEPLOYMENT strategy to Recreate and setting sm-app image to $REFACTOR_IMAGE..."
  tess kubectl --context="$CLUSTER" -n "$NAMESPACE" patch deployment "$DEPLOYMENT" --type='json' -p='[
    {"op": "replace", "path": "/spec/strategy", "value": {"type": "Recreate"}},
    {"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "'"$REFACTOR_IMAGE"'"}
  ]'

  sleep 40

  # Step 2: Get new pod name and check the log
  NEW_POD=$(tess kubectl --context="$CLUSTER" -n "$NAMESPACE" get pods -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep "$DEPLOYMENT" | grep -v "$POD")
  while [[ -z "$NEW_POD" ]]; do
    echo "[Step 2]. No new pod found for deployment $DEPLOYMENT. deployment still upgrading, wait 3s and retrying."
    sleep 3
    NEW_POD=$(tess kubectl --context="$CLUSTER" -n "$NAMESPACE" get pods -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep "$DEPLOYMENT" | grep -v "$POD")
  done
  echo "[Step 2]. New pod created: $NEW_POD for deployment $DEPLOYMENT."
  echo "[Step 2]. Checking logs for new pod $NEW_POD..."
  max_retry_cnt=20
  retry_cnt=0
  while ! check_pod_logs "$NEW_POD" "exit status 0;"; do
    if [[ $retry_cnt -ge $max_retry_cnt ]]; then
      echo "[Step 2. Exceeded maximum retries while checking logs for new pod $NEW_POD."
      exit 1
    fi
    echo "[Step 2]. Expected log message not found in new pod $NEW_POD, sleeping 3s and retrying."
    sleep 3
    retry_cnt=$((retry_cnt + 1))
  done
  echo "[Step 2]. refactor confirmation log found in new pod $NEW_POD."

  # Double Check deployment status again, expecting it to not be ready
  if check_deployment_status "$DEPLOYMENT"; then
    echo "[Step 2]. Unexpected! Deployment $DEPLOYMENT is still ready after updating to refactor image for pod $POD."
    exit 1
  fi

  # Step 3: Update deployment sm-app image to new image
  echo "[Step 3]. Updating deployment $DEPLOYMENT to use new image $NEW_IMAGE for pod $NEW_POD..."
  tess kubectl --context="$CLUSTER" -n "$NAMESPACE" set image deployment/"$DEPLOYMENT" sm-app="$NEW_IMAGE"
  sleep 40

  # Step 4: Check deployment status again, expecting it to be ready
  while ! check_deployment_status "$DEPLOYMENT"; do
    echo "[Step 4]. Deployment $DEPLOYMENT is not ready after updating to new image for pod $NEW_POD. sleep 5s and retrying."
    sleep 5
  done

  # Step 5: Update deployment strategy back to RollingUpdate and set maxUnavailable and maxSurge
  echo "[Step 5]. Updating deployment $DEPLOYMENT strategy back to RollingUpdate with maxUnavailable=0 and maxSurge=1..."
  tess kubectl --context="$CLUSTER" -n "$NAMESPACE" patch deployment "$DEPLOYMENT" --type='json' -p='[
    {"op": "replace", "path": "/spec/strategy", "value": {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 1, "maxSurge": 1}}}
  ]'

  # Final check to ensure deployment is ready
  while ! check_deployment_status "$DEPLOYMENT"; do
    echo "[Step 6].  Deployment $DEPLOYMENT is not ready after updating strategy back to RollingUpdate. sleep 5s and retrying."
    sleep 5
  done

  echo "[Step 6]. Deployment $DEPLOYMENT processed successfully."
done

echo "All pods processed successfully."
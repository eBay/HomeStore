#!/bin/bash

# Input parameters
CLUSTER=908
NAMESPACE="nuobject2sm-dev"
DEPLOYMENT_COUNT=1
REFACTOR_IMAGE="hub.tess.io/yawzhang/storage_mgr:refactor_new-RelWithDebInfo"
NEW_IMAGE="hub.tess.io/sds/storage_mgr:1.0-pre.0.2.6.6-RelWithDebInfo"
NODE_NAME="tess-node-xkbtd-tess908.sddz.ebay.com"
DEPLOYMENT_REGEX="nuobject2-isofruit-cherry-908-sm1"
LOG_FILE="logs/refactor.log"

if [[ -z "$NODE_NAME" ]]; then
  echo "please update node name in the script"
  exit 1
fi

# Function to log messages with timestamps
log_with_timestamp() {
  local message="$1"
  echo "$(date '+%Y-%m-%d %H:%M:%S') $message" | tee -a "$LOG_FILE"
}

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

PODS=$(tess kubectl --context="$CLUSTER" -n "$NAMESPACE" get pods --field-selector spec.nodeName="$NODE_NAME" -o jsonpath='{.items[*].metadata.name}')
if [[ -z "$PODS" ]]; then
  log_with_timestamp "No pods found on node $NODE_NAME."
  exit 0
fi

log_with_timestamp "node $NODE_NAME has pods [$PODS]"

process_cnt=0
for POD in $PODS; do
  DEPLOYMENT=$(tess kubectl --context="$CLUSTER" -n "$NAMESPACE" get pod "$POD" -o jsonpath='{.metadata.ownerReferences[?(@.kind=="ReplicaSet")].name}' | sed 's/-[a-z0-9]*$//')
  if [[ -z "$DEPLOYMENT" ]]; then
    log_with_timestamp "No deployment found for pod $POD. Skipping..."
    continue
#  elif ! [[ $DEPLOYMENT =~ $DEPLOYMENT_REGEX ]]; then
  elif ! [[ $DEPLOYMENT == $DEPLOYMENT_REGEX ]]; then
    log_with_timestamp "Skipping pod $POD as its deployment $DEPLOYMENT does not match the expected pattern."
    continue
  fi
  log_with_timestamp "Processing deployment $DEPLOYMENT pod $POD..."

  # PRE-CHECK
  CURRENT_IMAGE=$(tess kubectl --context="$CLUSTER" -n "$NAMESPACE" get pod "$POD" -o jsonpath='{.spec.containers[?(@.name=="sm-app")].image}')
  if [[ "$CURRENT_IMAGE" == "$NEW_IMAGE" ]]; then
    log_with_timestamp "[PRE-CHECK] Pod $POD is already using the new image $NEW_IMAGE. Skipping..."
    continue
  fi

  if [[ $process_cnt -ge $DEPLOYMENT_COUNT ]]; then
    log_with_timestamp "Reached the maximum number of deployments to process: $DEPLOYMENT_COUNT. Stopping further processing."
    break
  fi

  # Step 1: Update deployment strategy to Recreate and set sm-app image to refactor image
  log_with_timestamp "[Step 1]. Updating deployment $DEPLOYMENT strategy to Recreate and setting sm-app image to $REFACTOR_IMAGE..."
  tess kubectl --context="$CLUSTER" -n "$NAMESPACE" patch deployment "$DEPLOYMENT" --type='json' -p='[
    {"op": "replace", "path": "/spec/strategy", "value": {"type": "Recreate"}},
    {"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": "'"$REFACTOR_IMAGE"'"}
  ]'

  sleep 60

  # Step 2: Get new pod name and check the log
  NEW_POD=$(tess kubectl --context="$CLUSTER" -n "$NAMESPACE" get pods -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep "$DEPLOYMENT" | grep -v "$POD")
  while [[ -z "$NEW_POD" ]]; do
    log_with_timestamp "[Step 2]. No new pod found for deployment $DEPLOYMENT. deployment still upgrading, wait 3s and retrying."
    sleep 3
    NEW_POD=$(tess kubectl --context="$CLUSTER" -n "$NAMESPACE" get pods -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep "$DEPLOYMENT" | grep -v "$POD")
  done
  log_with_timestamp "[Step 2]. New pod created: $NEW_POD for deployment $DEPLOYMENT."
  log_with_timestamp "[Step 2]. Checking logs for new pod $NEW_POD..."
  max_retry_cnt=20
  retry_cnt=0
  while ! check_pod_logs "$NEW_POD" "exit status 0;"; do
    if [[ $retry_cnt -ge $max_retry_cnt ]]; then
      log_with_timestamp "[Step 2]. Exceeded maximum retries while checking logs for new pod $NEW_POD."
      exit 1
    fi
    log_with_timestamp "[Step 2]. Expected log message not found in new pod $NEW_POD, sleeping 3s and retrying."
    sleep 3
    retry_cnt=$((retry_cnt + 1))
  done
  log_with_timestamp "[Step 2]. refactor confirmation log found in new pod $NEW_POD."

  # Double Check deployment status again, expecting it to not be ready
  if check_deployment_status "$DEPLOYMENT"; then
    log_with_timestamp "[Step 2]. Unexpected! Deployment $DEPLOYMENT is still ready after updating to refactor image for pod $POD."
    exit 1
  fi

  # Step 3: Update deployment sm-app image to new image
  log_with_timestamp "[Step 3]. Updating deployment $DEPLOYMENT to use new image $NEW_IMAGE for pod $NEW_POD..."
  tess kubectl --context="$CLUSTER" -n "$NAMESPACE" set image deployment/"$DEPLOYMENT" sm-app="$NEW_IMAGE"
  sleep 40

  # Step 4: Check deployment status again, expecting it to be ready
  while ! check_deployment_status "$DEPLOYMENT"; do
    log_with_timestamp "[Step 4]. Deployment $DEPLOYMENT is not ready after updating to new image for pod $NEW_POD. sleep 5s and retrying."
    sleep 5
  done

  # Step 5: Update deployment strategy back to RollingUpdate and set maxUnavailable and maxSurge
  log_with_timestamp "[Step 5]. Updating deployment $DEPLOYMENT strategy back to RollingUpdate with maxUnavailable=0 and maxSurge=1..."
  tess kubectl --context="$CLUSTER" -n "$NAMESPACE" patch deployment "$DEPLOYMENT" --type='json' -p='[
    {"op": "replace", "path": "/spec/strategy", "value": {"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 1, "maxSurge": 1}}}
  ]'

  # Final check to ensure deployment is ready
  while ! check_deployment_status "$DEPLOYMENT"; do
    log_with_timestamp "[Step 6]. Deployment $DEPLOYMENT is not ready after updating strategy back to RollingUpdate. sleep 5s and retrying."
    sleep 5
  done

  log_with_timestamp "[Step 6]. Deployment $DEPLOYMENT processed successfully."
  process_cnt=$((process_cnt + 1))
  sleep 60
done

log_with_timestamp "All pods processed successfully."
// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

const redisTaskPrelude = `
local function current_millis()
  local value = redis.call('TIME')
  return (tonumber(value[1]) * 1000) + math.floor(tonumber(value[2]) / 1000)
end

local function decoded(raw)
  if not raw then return nil end
  local ok, value = pcall(cjson.decode, raw)
  if not ok or type(value) ~= 'table' then return nil end
  return value
end

local function valid_revision(value)
  return type(value) == 'number' and value >= 1 and value <= 9007199254740991 and value % 1 == 0
end
`

const redisTaskRegisterParticipantScript = redisTaskPrelude + `
local existing = redis.call('GET', KEYS[1])
if existing then
  if existing == ARGV[1] then
    redis.call('SET', KEYS[2], tostring(current_millis()))
    return 'IDEMPOTENT_BARRIER'
  end
  return 'ALREADY_EXISTS'
end
if not decoded(ARGV[1]) then return 'CORRUPT' end
redis.call('SET', KEYS[1], ARGV[1])
return 'REGISTERED'
`

const redisTaskLookupScript = `
local raw = redis.call('GET', KEYS[1])
if not raw then return 'NOT_FOUND' end
return 'FOUND\n' .. raw
`

const redisTaskCommitAssignmentScript = redisTaskPrelude + `
local expected = tonumber(ARGV[1])
local next = decoded(ARGV[2])
local committed = decoded(ARGV[3])
if not expected or expected < 0 or expected > 9007199254740991 or expected % 1 ~= 0 or
   not next or not valid_revision(next.revision) or next.revision ~= expected + 1 or
   not committed or committed.schema ~= 'urn:asb:taskcoord:redis:event:v1' then
  return 'CORRUPT'
end

local existing_event = redis.call('GET', KEYS[2])
if existing_event then
  if existing_event == ARGV[3] then
    redis.call('SET', KEYS[5], tostring(current_millis()))
    return 'IDEMPOTENT_BARRIER'
  end
  return 'EVENT_CONFLICT'
end
if redis.call('HEXISTS', KEYS[3], ARGV[4]) ~= 0 then return 'CORRUPT' end

local current_raw = redis.call('GET', KEYS[1])
if expected == 0 then
  if current_raw then return 'ALREADY_EXISTS' end
else
  local current = decoded(current_raw)
  if not current or not valid_revision(current.revision) then return 'REVISION_CONFLICT' end
  if current.revision ~= expected then return 'REVISION_CONFLICT' end
  if current_raw ~= ARGV[6] then return 'REVISION_CONFLICT' end
end

local outbox = decoded(ARGV[5])
if not outbox then return 'CORRUPT' end
local now = current_millis()
redis.call('SET', KEYS[1], ARGV[2])
redis.call('SET', KEYS[2], ARGV[3])
redis.call('HSET', KEYS[3], ARGV[4], ARGV[5])
redis.call('ZADD', KEYS[4], now, ARGV[4])
return 'CREATED'
`

const redisTaskCommitDelegationScript = redisTaskPrelude + `
local expected = tonumber(ARGV[1])
local parent = decoded(ARGV[2])
local child = decoded(ARGV[3])
local parent_event = decoded(ARGV[4])
local child_event = decoded(ARGV[5])
local delegation = decoded(ARGV[6])
if not expected or expected < 1 or expected > 9007199254740991 or expected % 1 ~= 0 or
   not parent or not child or not valid_revision(parent.revision) or parent.revision ~= expected + 1 or
   not valid_revision(child.revision) or child.revision ~= 1 or not parent_event or not child_event or not delegation then
  return 'CORRUPT'
end

local seen_parent = redis.call('GET', KEYS[3])
local seen_child = redis.call('GET', KEYS[4])
if seen_parent or seen_child then
  if seen_parent == ARGV[4] and seen_child == ARGV[5] and redis.call('GET', KEYS[5]) == ARGV[6] then
    redis.call('SET', KEYS[8], tostring(current_millis()))
    return 'IDEMPOTENT_BARRIER'
  end
  return 'EVENT_CONFLICT'
end
if redis.call('HEXISTS', KEYS[6], ARGV[7]) ~= 0 then return 'CORRUPT' end

local current_raw = redis.call('GET', KEYS[1])
local current = decoded(current_raw)
if not current or not valid_revision(current.revision) or current.revision ~= expected then
  return 'REVISION_CONFLICT'
end
if current_raw ~= ARGV[9] then return 'REVISION_CONFLICT' end
if redis.call('EXISTS', KEYS[2]) ~= 0 then return 'ALREADY_EXISTS' end
if redis.call('EXISTS', KEYS[5]) ~= 0 then return 'ALREADY_EXISTS' end
if not decoded(ARGV[8]) then return 'CORRUPT' end

local now = current_millis()
redis.call('SET', KEYS[1], ARGV[2])
redis.call('SET', KEYS[2], ARGV[3])
redis.call('SET', KEYS[3], ARGV[4])
redis.call('SET', KEYS[4], ARGV[5])
redis.call('SET', KEYS[5], ARGV[6])
redis.call('HSET', KEYS[6], ARGV[7], ARGV[8])
redis.call('ZADD', KEYS[7], now, ARGV[7])
return 'CREATED'
`

const redisTaskAppendInteractionScript = redisTaskPrelude + `
local event = decoded(ARGV[1])
local committed = decoded(ARGV[2])
local max_history = tonumber(ARGV[5])
if not event or not committed or not max_history or max_history < 1 then return 'CORRUPT' end

local seen = redis.call('GET', KEYS[3])
if seen then
  if seen == ARGV[2] then
    redis.call('SET', KEYS[11], tostring(current_millis()))
    return 'IDEMPOTENT_BARRIER'
  end
  return 'EVENT_CONFLICT'
end
if redis.call('EXISTS', KEYS[4]) ~= 0 then return 'EVENT_CONFLICT' end
if redis.call('HEXISTS', KEYS[9], ARGV[3]) ~= 0 then return 'CORRUPT' end

local assignment = decoded(redis.call('GET', KEYS[1]))
if not assignment then return 'NOT_FOUND' end
if assignment.assignment_id ~= event.assignment_id or assignment.task_id ~= event.task_id then
  return 'INVALID_INTERACTION'
end
local participant = decoded(redis.call('GET', KEYS[2]))
if not participant then return 'NOT_FOUND' end
if participant.participant_id ~= event.participant_id then return 'INVALID_INTERACTION' end
if participant.status ~= 'ACTIVE' then return 'PARTICIPANT_UNAVAILABLE' end

local in_reply_to = event.in_reply_to or ''
local supersedes = event.supersedes or ''
if event.kind == 'QUESTION' and in_reply_to == '' then
  if redis.call('LLEN', KEYS[7]) ~= 0 then return 'INVALID_INTERACTION' end
else
  local reply = decoded(redis.call('GET', KEYS[5]))
  if not reply or reply.event_id ~= in_reply_to or reply.interaction_id ~= event.interaction_id or
     reply.task_id ~= event.task_id or reply.assignment_id ~= event.assignment_id then
    return 'INVALID_INTERACTION'
  end
  if event.kind == 'QUESTION' then
    if reply.kind ~= 'RESPONSE' and reply.kind ~= 'CORRECTION' then return 'INVALID_INTERACTION' end
  else
    if reply.kind ~= 'QUESTION' then return 'INVALID_INTERACTION' end
    if event.kind ~= 'RESPONSE' then
      local prior = decoded(redis.call('GET', KEYS[6]))
      if not prior or prior.event_id ~= supersedes or prior.interaction_id ~= event.interaction_id or
         prior.task_id ~= event.task_id or prior.assignment_id ~= event.assignment_id or
         prior.in_reply_to ~= in_reply_to or
         (prior.kind ~= 'RESPONSE' and prior.kind ~= 'CORRECTION') or
         prior.participant_id ~= event.participant_id then
        return 'INVALID_INTERACTION'
      end
    end
  end
end

local bytes = tonumber(redis.call('GET', KEYS[8]) or '0')
if not bytes or bytes < 0 or bytes + string.len(ARGV[1]) > max_history then return 'LIMIT_REACHED' end
if not decoded(ARGV[4]) then return 'CORRUPT' end
local now = current_millis()
redis.call('SET', KEYS[3], ARGV[2])
redis.call('SET', KEYS[4], ARGV[1])
redis.call('RPUSH', KEYS[7], KEYS[4])
redis.call('SET', KEYS[8], bytes + string.len(ARGV[1]))
redis.call('HSET', KEYS[9], ARGV[3], ARGV[4])
redis.call('ZADD', KEYS[10], now, ARGV[3])
return 'APPENDED'
`

const redisTaskListInteractionsScript = `
local max_history = tonumber(ARGV[1])
if not max_history or max_history < 1 then return 'CORRUPT' end
local keys = redis.call('LRANGE', KEYS[1], 0, -1)
if #keys == 0 then return 'NOT_FOUND' end
local result = {}
local bytes = 0
for _, key in ipairs(keys) do
  local raw = redis.call('GET', key)
  if not raw then return 'CORRUPT' end
  bytes = bytes + string.len(raw)
  if bytes > max_history then return 'LIMIT_REACHED' end
  local ok, value = pcall(cjson.decode, raw)
  if not ok or type(value) ~= 'table' then return 'CORRUPT' end
  table.insert(result, value)
end
return 'FOUND\n' .. cjson.encode(result)
`

const redisTaskPollOutboxScript = redisTaskPrelude + `
local limit = tonumber(ARGV[3])
local lease_ms = tonumber(ARGV[4])
if not limit or limit < 1 or limit % 1 ~= 0 or not lease_ms or lease_ms < 1 then return 'CORRUPT' end
local now = current_millis()
local expired = redis.call('ZRANGEBYSCORE', KEYS[3], '-inf', now, 'LIMIT', 0, limit)
local candidates = {}
local selected = {}
for _, delivery_id in ipairs(expired) do
  if not selected[delivery_id] then
    table.insert(candidates, delivery_id)
    selected[delivery_id] = true
  end
end
local remaining = limit - #candidates
if remaining > 0 then
  local ready = redis.call('ZRANGE', KEYS[2], 0, remaining - 1)
  for _, delivery_id in ipairs(ready) do
    if not selected[delivery_id] then
      table.insert(candidates, delivery_id)
      selected[delivery_id] = true
    end
  end
end
if #candidates == 0 then return 'EMPTY' end

local raw_events = {}
for _, delivery_id in ipairs(candidates) do
  local raw = redis.call('HGET', KEYS[1], delivery_id)
  local event = decoded(raw)
  if not event then return 'CORRUPT' end
  raw_events[delivery_id] = raw
end

local lease_until = now + lease_ms
local deliveries = {}
for _, delivery_id in ipairs(candidates) do
  redis.call('ZREM', KEYS[2], delivery_id)
  redis.call('ZADD', KEYS[3], lease_until, delivery_id)
  redis.call('HSET', KEYS[4], delivery_id, ARGV[1])
  redis.call('HSET', KEYS[5], delivery_id, ARGV[2])
  table.insert(deliveries, {delivery_id = delivery_id, lease_id = ARGV[1], event_json = raw_events[delivery_id]})
end
return 'CLAIMED\n' .. cjson.encode(deliveries)
`

const redisTaskAcknowledgeOutboxScript = redisTaskPrelude + `
local owner = redis.call('HGET', KEYS[4], ARGV[1])
if not owner then return 'OUTBOX_CONFLICT' end
if owner ~= ARGV[2] then return 'OUTBOX_CONFLICT' end
local consumer = redis.call('HGET', KEYS[5], ARGV[1])
if not consumer or consumer ~= ARGV[3] then return 'OUTBOX_CONFLICT' end
local lease_until = tonumber(redis.call('ZSCORE', KEYS[3], ARGV[1]))
if not lease_until then return 'OUTBOX_CONFLICT' end
if lease_until <= current_millis() then return 'LEASE_EXPIRED' end
redis.call('HDEL', KEYS[1], ARGV[1])
redis.call('ZREM', KEYS[2], ARGV[1])
redis.call('ZREM', KEYS[3], ARGV[1])
redis.call('HDEL', KEYS[4], ARGV[1])
redis.call('HDEL', KEYS[5], ARGV[1])
return 'ACKED'
`

// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package production

const redisOperationRecordPrelude = `
local record_schema = 'urn:asb:operation-journal:redis:v1'

local function current_millis()
  local value = redis.call('TIME')
  return (tonumber(value[1]) * 1000) + math.floor(tonumber(value[2]) / 1000)
end

local function decode_record(raw)
  local ok, record = pcall(cjson.decode, raw)
  if not ok or type(record) ~= 'table' then
    return nil
  end
  if record.schema ~= record_schema or type(record.request_digest) ~= 'string' or
     type(record.state) ~= 'string' or type(record.outcome_digest) ~= 'string' or
     type(record.revision) ~= 'number' or type(record.created_at_ms) ~= 'number' or
     type(record.updated_at_ms) ~= 'number' or type(record.started_at_ms) ~= 'number' or
     type(record.completed_at_ms) ~= 'number' then
    return nil
  end
  if record.revision < 1 or record.revision > 9007199254740991 or record.revision % 1 ~= 0 or
     record.created_at_ms < 1 or record.created_at_ms > 253402300799999 or
     record.updated_at_ms < record.created_at_ms or record.updated_at_ms > 253402300799999 or
     record.started_at_ms < 0 or record.started_at_ms > record.updated_at_ms or
     (record.started_at_ms ~= 0 and record.started_at_ms < record.created_at_ms) or
     record.completed_at_ms < 0 or record.completed_at_ms > record.updated_at_ms then
    return nil
  end
  if record.state == 'ACCEPTED' then
    if record.started_at_ms ~= 0 or record.completed_at_ms ~= 0 or record.outcome_digest ~= '' then return nil end
  elseif record.state == 'RUNNING' or record.state == 'INDETERMINATE' then
    if record.started_at_ms < record.created_at_ms or record.completed_at_ms ~= 0 or record.outcome_digest ~= '' then return nil end
  elseif record.state == 'SUCCEEDED' or record.state == 'FAILED' then
    if record.started_at_ms < record.created_at_ms or record.completed_at_ms ~= record.updated_at_ms then return nil end
  elseif record.state == 'CANCELED' then
    if record.completed_at_ms ~= record.updated_at_ms then return nil end
  else
    return nil
  end
  return record
end

local function encoded(record)
  return cjson.encode(record)
end

local function exact_record(key, request_digest)
  local raw = redis.call('GET', key)
  if not raw then
    return nil, 'NOT_FOUND'
  end
  local record = decode_record(raw)
  if not record then
    return nil, 'CORRUPT'
  end
  if record.request_digest ~= request_digest then
    return nil, 'CONFLICT'
  end
  return record, nil
end
`

const redisReserveOperationScript = redisOperationRecordPrelude + `
local raw = redis.call('GET', KEYS[1])
if raw then
  local record = decode_record(raw)
  if not record then return 'CORRUPT' end
  if record.request_digest ~= ARGV[1] then return 'CONFLICT' end
  return 'EXISTING\n' .. raw
end

local now = current_millis()
local record = {
  schema = record_schema,
  request_digest = ARGV[1],
  state = 'ACCEPTED',
  outcome_digest = '',
  revision = 1,
  created_at_ms = now,
  updated_at_ms = now,
  started_at_ms = 0,
  completed_at_ms = 0
}
local value = encoded(record)
redis.call('SET', KEYS[1], value)
return 'CREATED\n' .. value
`

const redisReserveAcceptanceScript = redisOperationRecordPrelude + `
if redis.call('EXISTS', KEYS[2]) ~= 0 then
  return 'REPLAY'
end

local now = current_millis()
local retain_until = tonumber(ARGV[2])
local max_replay_ttl = tonumber(ARGV[3])
if not retain_until or not max_replay_ttl then return 'INVALID' end
local replay_ttl = math.floor(retain_until - now)
if replay_ttl < 1 then return 'EXPIRED' end
if replay_ttl > max_replay_ttl then return 'TTL_TOO_LONG' end

local raw = redis.call('GET', KEYS[1])
local created = false
if raw then
  local existing = decode_record(raw)
  if not existing then return 'CORRUPT' end
  if existing.request_digest ~= ARGV[1] then return 'CONFLICT' end
else
  local record = {
    schema = record_schema,
    request_digest = ARGV[1],
    state = 'ACCEPTED',
    outcome_digest = '',
    revision = 1,
    created_at_ms = now,
    updated_at_ms = now,
    started_at_ms = 0,
    completed_at_ms = 0
  }
  raw = encoded(record)
  created = true
end

local replay_set = redis.call('SET', KEYS[2], '1', 'PX', replay_ttl, 'NX')
if not replay_set then return 'REPLAY' end
if created then
  redis.call('SET', KEYS[1], raw)
  return 'CREATED\n' .. raw
end
return 'REPLAY_RESERVED\n' .. raw
`

const redisLookupOperationScript = redisOperationRecordPrelude + `
local record, problem = exact_record(KEYS[1], ARGV[1])
if problem then return problem end
return 'FOUND\n' .. encoded(record)
`

const redisMarkRunningScript = redisOperationRecordPrelude + `
local record, problem = exact_record(KEYS[1], ARGV[1])
if problem then return problem end
if record.state == 'RUNNING' then
  return 'IDEMPOTENT\n' .. encoded(record)
end
if record.state ~= 'ACCEPTED' then return 'INVALID_TRANSITION' end
local now = current_millis()
if now < record.updated_at_ms then now = record.updated_at_ms end
record.state = 'RUNNING'
record.revision = record.revision + 1
record.started_at_ms = now
record.updated_at_ms = now
local value = encoded(record)
redis.call('SET', KEYS[1], value)
return 'UPDATED\n' .. value
`

const redisMarkIndeterminateScript = redisOperationRecordPrelude + `
local record, problem = exact_record(KEYS[1], ARGV[1])
if problem then return problem end
if record.state == 'INDETERMINATE' then
  return 'IDEMPOTENT\n' .. encoded(record)
end
if record.state ~= 'RUNNING' then return 'INVALID_TRANSITION' end
local now = current_millis()
if now < record.updated_at_ms then now = record.updated_at_ms end
record.state = 'INDETERMINATE'
record.revision = record.revision + 1
record.updated_at_ms = now
local value = encoded(record)
redis.call('SET', KEYS[1], value)
return 'UPDATED\n' .. value
`

const redisFinalizeOperationScript = redisOperationRecordPrelude + `
local record, problem = exact_record(KEYS[1], ARGV[1])
if problem then return problem end
local final_state = ARGV[2]
local outcome_digest = ARGV[3]
if record.state == 'SUCCEEDED' or record.state == 'FAILED' or record.state == 'CANCELED' then
  if record.state == final_state and record.outcome_digest == outcome_digest then
    return 'IDEMPOTENT\n' .. encoded(record)
  end
  return 'CONFLICT'
end
if record.state == 'ACCEPTED' and final_state ~= 'CANCELED' then return 'INVALID_TRANSITION' end
if record.state ~= 'ACCEPTED' and record.state ~= 'RUNNING' and record.state ~= 'INDETERMINATE' then
  return 'INVALID_TRANSITION'
end
local now = current_millis()
if now < record.updated_at_ms then now = record.updated_at_ms end
record.state = final_state
record.outcome_digest = outcome_digest
record.revision = record.revision + 1
record.updated_at_ms = now
record.completed_at_ms = now
local value = encoded(record)
redis.call('SET', KEYS[1], value)
return 'UPDATED\n' .. value
`

const redisFinalizeResultScript = redisOperationRecordPrelude + `
local record, problem = exact_record(KEYS[1], ARGV[1])
if problem then return problem end
local outcome_digest = ARGV[2]
local sealed_result = ARGV[3]
local existing_result = redis.call('GET', KEYS[2])

if record.state == 'SUCCEEDED' then
  if record.outcome_digest == outcome_digest and existing_result and existing_result == sealed_result then
    return 'IDEMPOTENT\n' .. encoded(record)
  end
  return 'CONFLICT'
end
if record.state == 'FAILED' or record.state == 'CANCELED' then return 'CONFLICT' end
if existing_result then return 'CORRUPT' end
if record.state ~= 'RUNNING' and record.state ~= 'INDETERMINATE' then return 'INVALID_TRANSITION' end

local now = current_millis()
if now < record.updated_at_ms then now = record.updated_at_ms end
record.state = 'SUCCEEDED'
record.outcome_digest = outcome_digest
record.revision = record.revision + 1
record.updated_at_ms = now
record.completed_at_ms = now
local value = encoded(record)
redis.call('SET', KEYS[2], sealed_result)
redis.call('SET', KEYS[1], value)
return 'COMPLETED\n' .. value
`

const redisLookupResultScript = redisOperationRecordPrelude + `
local record, problem = exact_record(KEYS[1], ARGV[1])
if problem then return problem end
if record.state ~= 'SUCCEEDED' or record.outcome_digest == '' then return 'INVALID_TRANSITION' end
local result = redis.call('GET', KEYS[2])
if not result then return 'NO_RESULT' end
return 'FOUND_RESULT\n' .. encoded(record) .. '\n' .. result
`

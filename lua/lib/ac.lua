--[[
  btwaf_ce / lib/ac.lua
  Aho-Corasick 多模式匹配（纯 Lua，contract §6.5 / §9.3）。
  自动机格式：
    { words = {...}, next = { [state] = { [byte] = next_state } },
      fail = { [state] = state }, out = { [state] = {word_index, ...} } }
  首状态为 0；大小写敏感（调用方先用 lowercase 变换）。
  ac.build(words) 为构建期辅助实现（rules 组用 Python 生成，此函数用于测试/小列表）。
]]

local ac = {}

-- 匹配：命中返回 word 字符串与结束位置；未命中返回 nil
function ac.match(automaton, text)
  if type(automaton) ~= "table" or type(text) ~= "string" or text == "" then
    return nil
  end
  local nxt = automaton.next
  local fail = automaton.fail
  local out = automaton.out
  local words = automaton.words
  if type(nxt) ~= "table" or type(words) ~= "table" then
    return nil
  end
  local state = 0
  local len = #text
  for i = 1, len do
    local b = string.byte(text, i)
    -- 沿失效链回溯找可转移状态
    while true do
      local row = nxt[state]
      local ns = row and row[b]
      if ns then
        state = ns
        break
      end
      if state == 0 then
        break
      end
      state = fail[state] or 0
    end
    -- 检查当前状态与失效链上的输出（兼容未合并输出的自动机）
    local st = state
    while st ~= 0 do
      local o = out[st]
      if o and #o > 0 then
        return words[o[1]], i
      end
      st = fail[st] or 0
    end
    local o0 = out[0]
    if o0 and #o0 > 0 then
      return words[o0[1]], i
    end
  end
  return nil
end

-- 构建自动机（BFS 计算 fail 链，合并输出）
function ac.build(words)
  local automaton = { words = {}, next = {}, fail = {}, out = {} }
  local count = 0
  local function new_state()
    local st = count
    count = count + 1
    automaton.next[st] = {}
    automaton.fail[st] = 0
    return st
  end
  new_state() -- state 0

  -- 插入阶段
  local word_map = {}
  for idx = 1, #words do
    local w = tostring(words[idx])
    if w ~= "" then
      word_map[w] = word_map[w] or (#automaton.words + 1)
      if not word_map[w] then
        word_map[w] = #automaton.words + 1
      end
      local wid = word_map[w]
      automaton.words[wid] = automaton.words[wid] or w
      local state = 0
      for i = 1, #w do
        local b = string.byte(w, i)
        local row = automaton.next[state]
        local ns = row[b]
        if not ns then
          ns = new_state()
          row[b] = ns
        end
        state = ns
      end
      automaton.out[state] = automaton.out[state] or {}
      automaton.out[state][#automaton.out[state] + 1] = wid
    end
  end

  -- BFS 计算 fail 链
  local queue = {}
  local qh, qt = 1, 0
  local row0 = automaton.next[0]
  for _, ns in pairs(row0) do
    automaton.fail[ns] = 0
    qt = qt + 1
    queue[qt] = ns
  end
  while qh <= qt do
    local state = queue[qh]
    qh = qh + 1
    local row = automaton.next[state]
    for b, ns in pairs(row) do
      local f = automaton.fail[state]
      local target
      while true do
        local frow = automaton.next[f]
        target = frow and frow[b]
        if target or f == 0 then
          break
        end
        f = automaton.fail[f] or 0
      end
      automaton.fail[ns] = target or 0
      -- 合并 fail 状态的输出，匹配时无需回溯整条链
      local fo = automaton.out[automaton.fail[ns]]
      if fo then
        automaton.out[ns] = automaton.out[ns] or {}
        for i = 1, #fo do
          automaton.out[ns][#automaton.out[ns] + 1] = fo[i]
        end
      end
      qt = qt + 1
      queue[qt] = ns
    end
  end
  return automaton
end

return ac

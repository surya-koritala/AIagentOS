<script>
  import { invoke } from '@tauri-apps/api/core';
  import { createEventDispatcher } from 'svelte';

  export let agentId = null;

  const dispatch = createEventDispatcher();
  let messages = [];
  let input = '';
  let loading = false;
  let messagesEl;

  $: if (messagesEl) {
    setTimeout(() => messagesEl.scrollTop = messagesEl.scrollHeight, 50);
  }

  async function sendMessage() {
    if (!input.trim() || !agentId || loading) return;
    const userMsg = input.trim();
    input = '';
    messages = [...messages, { role: 'user', content: userMsg }];
    loading = true;
    const operation = 'waiting for agent turn';
    dispatch('operation', { label: operation, active: true });

    try {
      const response = await invoke('send_message', { agentId, message: userMsg });
      messages = [...messages, {
        role: 'assistant',
        content: response.content,
        toolCalls: response.tool_calls_made,
        tokens: response.tokens_used,
      }];
      dispatch('messageSent');
    } catch (e) {
      messages = [...messages, { role: 'error', content: String(e) }];
    } finally {
      loading = false;
      dispatch('operation', { label: operation, active: false });
    }
  }

  function handleKeydown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }
</script>

<div class="chat-panel">
  {#if !agentId}
    <div class="empty">
      <div class="empty-icon" aria-hidden="true">💬</div>
      <p>Select an agent to start chatting</p>
    </div>
  {:else}
    <div class="chat-header">
      <h3>Chat</h3>
    </div>
    <div class="messages" bind:this={messagesEl} role="log" aria-live="polite" aria-relevant="additions text">
      {#each messages as msg}
        <div class="message {msg.role}">
          <div class="avatar" aria-hidden="true">{msg.role === 'user' ? '👤' : msg.role === 'error' ? '⚠️' : '🤖'}</div>
          <div class="bubble">
            <span class="visually-hidden">{msg.role === 'user' ? 'You' : msg.role === 'error' ? 'Error' : 'Agent'}:</span>
            <div class="content">{msg.content}</div>
            {#if msg.toolCalls}
              <div class="meta">
                <span><span aria-hidden="true">🔧</span> {msg.toolCalls} tool{msg.toolCalls > 1 ? 's' : ''} used</span>
                <span>· {msg.tokens} tokens</span>
              </div>
            {/if}
          </div>
        </div>
      {/each}
      {#if loading}
        <div class="message assistant" role="status">
          <div class="avatar" aria-hidden="true">🤖</div>
          <div class="bubble">
            <div class="thinking">
              <span class="dot-pulse" aria-hidden="true"></span> Agent is thinking…
            </div>
          </div>
        </div>
      {/if}
    </div>
    <div class="input-area">
      <label class="visually-hidden" for="chat-message">Message to the selected agent</label>
      <textarea
        id="chat-message"
        bind:value={input}
        on:keydown={handleKeydown}
        placeholder="Ask anything… (Enter to send)"
        rows="1"
        disabled={loading}
      ></textarea>
      <button aria-label="Send message" on:click={sendMessage} disabled={loading || !input.trim()}>
        <span aria-hidden="true">↑</span>
      </button>
    </div>
  {/if}
</div>

<style>
  .chat-panel { flex: 1; display: flex; flex-direction: column; height: 100%; background: #0f0f1a; }
  .empty { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: #b9b9c8; }
  .empty-icon { font-size: 3rem; margin-bottom: 0.5rem; }
  .chat-header { padding: 1rem 1.5rem; border-bottom: 1px solid #1e1e33; }
  .chat-header h3 { margin: 0; font-size: 0.9rem; color: #b9b9c8; }
  .messages { flex: 1; overflow-y: auto; padding: 1.5rem; display: flex; flex-direction: column; gap: 1rem; }
  .message { display: flex; gap: 0.75rem; align-items: flex-start; }
  .avatar { width: 32px; height: 32px; border-radius: 8px; background: #1a1a2e; display: flex; align-items: center; justify-content: center; font-size: 0.9rem; flex-shrink: 0; }
  .message.user { flex-direction: row-reverse; }
  .message.user .avatar { background: #1e2a44; }
  .bubble { max-width: 75%; padding: 0.75rem 1rem; border-radius: 12px; }
  .message.user .bubble { background: #1e2a44; border: 1px solid #2a3a55; }
  .message.assistant .bubble { background: #1a1a2e; border: 1px solid #2a2a44; }
  .message.error .bubble { background: #2a1a1a; border: 1px solid #3a2020; color: #f87171; }
  .content { white-space: pre-wrap; line-height: 1.5; }
  .meta { margin-top: 0.5rem; font-size: 0.7rem; color: #b9b9c8; display: flex; gap: 0.25rem; }
  .thinking { color: #b9b9c8; font-style: italic; display: flex; align-items: center; gap: 0.5rem; }
  .dot-pulse { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #4a90d9; animation: pulse 1s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 0.3; } 50% { opacity: 1; } }
  .input-area { display: flex; gap: 0.5rem; padding: 1rem 1.5rem; border-top: 1px solid #1e1e33; background: #12121f; }
  textarea { flex: 1; min-height: 44px; resize: none; padding: 0.65rem 1rem; border-radius: 10px; border: 1px solid #66667a; background: #1a1a2e; color: #eee; font-size: 0.9rem; font-family: inherit; line-height: 1.4; }
  textarea:focus { border-color: #8bc5ff; }
  textarea:disabled { opacity: 0.5; }
  button { min-width: 44px; min-height: 44px; border-radius: 10px; border: none; background: #3276bd; color: white; cursor: pointer; font-size: 1.1rem; display: flex; align-items: center; justify-content: center; align-self: flex-end; }
  button:disabled { opacity: 0.3; cursor: not-allowed; }
  button:hover:not(:disabled) { background: #5a9fe9; }
</style>

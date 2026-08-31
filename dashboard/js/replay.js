// Session replay viewer built on xterm.js. Plays back the frame list from
// GET /api/sessions/{id}/replay, which parser/main.py's _ttylog_to_frames()
// already reduced from Cowrie's binary TTY log format (see that function's
// docstring for the output/input-direction selection logic it ports from
// Cowrie's own scripts/asciinema.py and scripts/playlog.py).
//
// Not asciinema-player: that library's exact v3 embed API/CSS bundle would
// be unverified guesswork here, whereas xterm.js's create/open/write/reset
// surface is small and stable, and the gap-clamping below is the same
// "don't bore the viewer with silent stretches" idea as Cowrie's own
// playlog -m/--maxdelay (default 3.0s), just applied client-side so the
// speed selector can rescale it live.
//
// Requires: API_URL and authFetch() (js/data.js or search.html's own
// inline copy, and js/auth.js) already loaded, and window.Terminal
// (xterm.js) loaded before this file.

const REPLAY_MAX_GAP_SECONDS = 2.0

let _replayTerm = null
let _replayTimer = null
let _replayFrames = []
let _replayIndex = 0
let _replaySpeed = 1
let _replayPlaying = false

function _replayEls() {
  return {
    modal: document.getElementById('replay-modal'),
    status: document.getElementById('replay-status'),
    term: document.getElementById('replay-term'),
    playPause: document.getElementById('replay-playpause'),
    speed: document.getElementById('replay-speed'),
  }
}

function closeReplayModal() {
  const { modal } = _replayEls()
  if (modal) modal.style.display = 'none'
  _stopReplayTimer()
  if (_replayTerm) {
    _replayTerm.dispose()
    _replayTerm = null
  }
  _replayFrames = []
  _replayIndex = 0
}

async function playSessionReplay(sessionId) {
  const { modal, status, term, speed } = _replayEls()
  if (!modal || !term) return

  modal.style.display = 'flex'
  term.innerHTML = ''
  status.textContent = 'Đang tải bản ghi phiên...'
  if (speed) speed.value = '1'
  _replaySpeed = 1
  _replayFrames = []
  _replayIndex = 0

  _replayTerm = new Terminal({
    convertEol: true,
    fontSize: 13,
    disableStdin: true,
    theme: { background: '#0b0d14', foreground: '#e2e8f0' },
  })
  _replayTerm.open(term)

  try {
    const res = await authFetch(`${API_URL}/api/sessions/${encodeURIComponent(sessionId)}/replay`)
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      status.textContent = err.detail || 'Không tải được bản ghi phiên'
      return
    }
    const data = await res.json()
    _replayFrames = data.frames || []

    if (_replayFrames.length === 0) {
      status.textContent = 'Phiên này không có dữ liệu để phát lại'
      return
    }

    const durationLabel = Math.round(data.duration || 0)
    status.textContent = `IP: ${data.src_ip || '?'} — thời lượng ~${durationLabel}s` +
      (data.truncated ? ' (đã cắt bớt vì bản ghi quá dài)' : '')
    _startReplay()
  } catch (e) {
    status.textContent = 'Lỗi kết nối API'
  }
}

function _stopReplayTimer() {
  if (_replayTimer) {
    clearTimeout(_replayTimer)
    _replayTimer = null
  }
  _replayPlaying = false
  const { playPause } = _replayEls()
  if (playPause) playPause.textContent = '▶'
}

function _startReplay() {
  _replayPlaying = true
  const { playPause } = _replayEls()
  if (playPause) playPause.textContent = '⏸'
  _scheduleNextFrame()
}

function _scheduleNextFrame() {
  if (!_replayPlaying) return
  if (_replayIndex >= _replayFrames.length) {
    _stopReplayTimer()
    return
  }
  const frame = _replayFrames[_replayIndex]
  const prevT = _replayIndex > 0 ? _replayFrames[_replayIndex - 1].t : 0
  const gapSeconds = Math.min(Math.max(frame.t - prevT, 0), REPLAY_MAX_GAP_SECONDS)
  _replayTimer = setTimeout(() => {
    _replayTerm.write(frame.data)
    _replayIndex++
    _scheduleNextFrame()
  }, (gapSeconds * 1000) / _replaySpeed)
}

function toggleReplayPlayPause() {
  if (!_replayTerm) return
  if (_replayPlaying) {
    _stopReplayTimer()
  } else {
    _startReplay()
  }
}

function restartReplay() {
  if (!_replayTerm) return
  _stopReplayTimer()
  _replayIndex = 0
  _replayTerm.reset()
  _startReplay()
}

function setReplaySpeed(value) {
  _replaySpeed = parseFloat(value) || 1
}

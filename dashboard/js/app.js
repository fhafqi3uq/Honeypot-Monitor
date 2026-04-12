function updateStats(stats) {
  document.getElementById('stat-total').textContent   = stats.total
  document.getElementById('stat-ips').textContent     = stats.unique_ips
  document.getElementById('stat-failed').textContent  = stats.failed
  document.getElementById('stat-success').textContent = stats.success
}

function updateTable(attacks) {
  const tbody = document.getElementById('attack-tbody')
  tbody.innerHTML = attacks.map(a => {
    const isSuccess = a.event === 'cowrie.login.success'
    const isCommand = a.event === 'cowrie.command.input'
    const status    = isSuccess ? 'success' : 'failed'
    const label     = isSuccess ? '✓ Success' : isCommand ? '⌨ Command' : '✗ Failed'
    return `
      <tr>
        <td style="color:#94a3b8">${a.time}</td>
        <td class="ip-text">${a.ip}</td>
        <td>${a.username || '-'}</td>
        <td style="color:#94a3b8">${a.password || '-'}</td>
        <td style="color:#94a3b8">${a.event.replace('cowrie.','')}</td>
        <td><span class="badge ${status}">${label}</span></td>
      </tr>`
  }).join('')
}

function updateTime() {
  document.getElementById('last-updated').textContent =
    'Cập nhật lúc: ' + new Date().toLocaleTimeString('vi-VN')
}

async function loadData() {
  const [stats, attacks, hours, types] = await Promise.all([
    fetchStats(), fetchAttacks(), fetchHours(), fetchTypes()
  ])
  updateStats(stats)
  updateTable(attacks)
  initBarChart(hours)
  initPieChart(types)
  updateTime()
}

document.addEventListener('DOMContentLoaded', () => {
  loadData()
  setInterval(loadData, 30000)
})

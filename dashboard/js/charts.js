let barChart = null
let pieChart = null

function initBarChart(data) {
  const ctx = document.getElementById('barChart').getContext('2d')
  if (barChart) barChart.destroy()
  barChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: data.map(d => d.hour),
      datasets: [{ label:'Số tấn công', data: data.map(d => d.count), backgroundColor:'#3b82f6', borderRadius:4 }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display:false } },
      scales: {
        x: { ticks:{color:'#64748b'}, grid:{color:'#1a1f2e'} },
        y: { ticks:{color:'#64748b'}, grid:{color:'#1a1f2e'} },
      }
    }
  })
}

function initPieChart(data) {
  const ctx = document.getElementById('pieChart').getContext('2d')
  if (pieChart) pieChart.destroy()
  pieChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: data.labels,
      datasets: [{ data: data.values, backgroundColor:['#3b82f6','#ef4444','#f59e0b','#8b5cf6'], borderWidth:0 }]
    },
    options: {
      responsive: true,
      plugins: { legend: { position:'bottom', labels:{color:'#94a3b8', padding:16, font:{size:12}} } }
    }
  })
}

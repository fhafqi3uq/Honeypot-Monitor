let barChart = null
let pieChart = null

function initBarChart(data) {
  const ctx = document.getElementById('barChart').getContext('2d')
  if (barChart) barChart.destroy()
  const gradient = ctx.createLinearGradient(0, 0, 0, 220)
  gradient.addColorStop(0, '#3987e5')
  gradient.addColorStop(1, '#1c5cab')

  // Cột cuối cùng = giờ VN hiện tại, đang chạy dở (chưa đủ 60 phút dữ
  // liệu) - tô màu xanh NHẠT HƠN (không phải mờ/alpha thấp - một cột thấp
  // ở alpha thấp gần như biến mất trên nền tối, tự kiểm chứng bằng
  // screenshot) để vẫn luôn nhìn rõ dù giá trị nhỏ, nhưng rõ ràng khác với
  // gradient đậm của các giờ đã kết thúc trọn vẹn.
  const lastIndex = data.length - 1
  const colors = data.map((_, i) => i === lastIndex ? '#8ec5f7' : gradient)

  barChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: data.map(d => d.hour),
      datasets: [{ label:'Số tấn công', data: data.map(d => d.count), backgroundColor:colors, borderRadius:5, maxBarThickness:28 }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display:false },
        tooltip: {
          backgroundColor:'#171a26', borderColor:'rgba(255,255,255,.1)', borderWidth:1, padding:10, titleColor:'#eef1f8', bodyColor:'#9aa4bd',
          callbacks: {
            afterLabel: (item) => item.dataIndex === lastIndex ? '⏳ Giờ hiện tại - số liệu tạm tính' : undefined,
          },
        },
      },
      scales: {
        x: { ticks:{color:'#6b7590'}, grid:{display:false} },
        y: { ticks:{color:'#6b7590'}, grid:{color:'rgba(255,255,255,.06)'} },
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
      datasets: [{ data: data.values, backgroundColor:['#3987e5','#d95926','#9085e9','#e66767'], borderWidth:2, borderColor:'#12141e', hoverOffset:6 }]
    },
    options: {
      responsive: true,
      cutout:'62%',
      plugins: {
        legend: { position:'bottom', labels:{color:'#9aa4bd', padding:16, font:{size:12}, usePointStyle:true, pointStyle:'circle'} },
        tooltip:{ backgroundColor:'#171a26', borderColor:'rgba(255,255,255,.1)', borderWidth:1, padding:10, titleColor:'#eef1f8', bodyColor:'#9aa4bd' }
      }
    }
  })
}

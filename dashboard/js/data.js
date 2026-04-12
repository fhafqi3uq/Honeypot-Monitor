const MOCK_STATS = { total:344, unique_ips:1, failed:112, success:2 }

const MOCK_HOURS = [
  {hour:"00:00",count:8},{hour:"02:00",count:15},{hour:"04:00",count:22},
  {hour:"06:00",count:11},{hour:"08:00",count:34},{hour:"10:00",count:67},
  {hour:"12:00",count:45},{hour:"14:00",count:89},{hour:"16:00",count:54},
  {hour:"18:00",count:38},{hour:"20:00",count:72},{hour:"22:00",count:29},
]

const MOCK_TYPES = {
  labels: ["Brute-force SSH","Login Success","Command Input","Port Scan"],
  values: [112, 2, 6, 15]
}

const MOCK_ATTACKS = [
  {time:"14:23:01", ip:"185.220.101.45", username:"root",     password:"123456",    event:"cowrie.login.failed"  },
  {time:"14:23:15", ip:"45.33.32.156",   username:"admin",    password:"admin",     event:"cowrie.login.failed"  },
  {time:"14:25:02", ip:"103.21.244.0",   username:"root",     password:"toor",      event:"cowrie.login.success" },
  {time:"14:26:10", ip:"91.108.4.1",     username:"ubuntu",   password:"ubuntu",    event:"cowrie.login.failed"  },
  {time:"14:27:33", ip:"198.51.100.5",   username:"pi",       password:"raspberry", event:"cowrie.command.input" },
  {time:"14:28:01", ip:"203.0.113.42",   username:"root",     password:"password",  event:"cowrie.login.failed"  },
  {time:"14:29:55", ip:"77.88.55.66",    username:"oracle",   password:"oracle",    event:"cowrie.login.failed"  },
  {time:"14:30:12", ip:"1.2.3.4",        username:"postgres", password:"postgres",  event:"cowrie.login.failed"  },
]

async function fetchStats()   { return MOCK_STATS   }
async function fetchAttacks() { return MOCK_ATTACKS  }
async function fetchHours()   { return MOCK_HOURS    }
async function fetchTypes()   { return MOCK_TYPES    }

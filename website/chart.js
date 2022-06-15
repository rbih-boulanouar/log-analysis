
const ctx = document.getElementById('myChart').getContext('2d');
const test = document.getElementById('test').getContext('2d');
const myChart = new Chart(ctx, {
    type: 'pie',
    data: {
        labels: ['XSS', 'SQLI', 'Command Injection','Code Injection','CRLF Injection','LDAP Injection'],
        datasets: [{
            label: 'attempts of attacks',
            data: [5, 19, 3,1,6,4],
            backgroundColor: [
                'rgba(255, 99, 132,1)',
                'rgba(54, 162, 235,1)',
                'rgba(255, 206, 86, 1)',
                'rgba(75, 192, 192, 1)',
                'rgba(153, 102, 255, 1)',
                'rgba(255, 159, 64, 1)'
            ],
            
        }]
    },
    options: {
        responsive: true
    }
});

const myChatert = new Chart(test , {
    type: 'bar',
    data: {
        labels: ['XSS', 'SQLI', 'Command Injection','Code Injection','CRLF Injection','LDAP Injection'],
        datasets: [{
            label: 'attempts of attacks',
            data: [5, 19, 3,1,6,4],
            backgroundColor: [
                'rgba(255, 99, 132,1)',
                'rgba(54, 162, 235,1)',
                'rgba(255, 206, 86, 1)',
                'rgba(75, 192, 192, 1)',
                'rgba(153, 102, 255, 1)',
                'rgba(255, 159, 64, 1)'
            ],
            
        }]
    },
    options: 
    {
        responsive: true
    
    }
});



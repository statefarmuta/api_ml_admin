let labels1 = ['00:00','01:00','02:00','03:00','04:00','05:00','06:00','07:00','08:00',
'09:00','10:00','11:00','12:00','13:00','14:00','15:00','16:00','17:00','18:00','19:00','20:00','21:00','22:00','23:00']; 
let data1 = [0, 0, 0, 0, 0, 0, 0, 0, 1000, 200, 250, 300, 500, 1350, 10, 16, 17, 18, 19, 20, 21, 22, 23, 0];
let colors1 = ['#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA',
'#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA','#49A9EA'];

let myChart1 = document.getElementById("myChart1").getContext('2d');

let chart1 = new Chart (myChart1, {
    type: 'bar',
    
    data: {
        labels: labels1,
        datasets: [{
            data: data1,
            backgroundColor: colors1
        }]
    },
    
    options:{
        title:{
            text: "Total Steps per hour",
            display:true
        },
        scales: {
            yAxes: [{
                ticks: {
                    beginAtZero: true
                }
            }]
        },
        legend: {
            display: false
        }
    }

});

let labels2 = ['00:00','01:00','02:00','03:00','04:00','05:00','06:00','07:00','08:00',
'09:00','10:00','11:00','12:00','13:00','14:00','15:00','16:00','17:00','18:00','19:00','20:00','21:00','22:00','23:00']; 
let data2 = [60, 60, 60, 65, 66, 67, 70, 71, 75, 70, 69, 65, 71, 74, 75, 70, 65, 66, 67, 68, 66, 70, 71, 72];
let colors2 = ['#49A9EA'];

let myChart2 = document.getElementById("myChart2").getContext('2d');

let chart2 = new Chart (myChart2, {
    type: 'line',
    
    data: {
        labels: labels2,
        datasets: [{
            lineTension: 0.1,
            backgroundColor: "rgba(75,192,192,0.4)",
            borderColor: "rgba(75,192,192,1)",
            pointBorderColor:"rgba(75,192,192,1)",
            pointBackgroundColor: "#fff",
            pointBorderWidth: 1,
            pointHoverRadius: 5,
            pointHoverBackgroundColor: "rgba(75,192,192,1)",
            fill: false,
            data: data2,
            backgroundColor: colors2
        }]
    },
    
    options:{
        title:{
            text: "Average heart rate",
            display:true
        },
        scales: {
            yAxes: [{
                ticks: {
                    beginAtZero: true
                }
            }]
        },
        legend: {
            display: false
        }
    }

});

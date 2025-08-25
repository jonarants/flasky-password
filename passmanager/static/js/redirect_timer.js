document.addEventListener('DOMContentLoaded', function() {
    const countdownElementLogin = document.getElementById('countdown-redirect-login');
    const countdownElementDashboard = document.getElementById('countdown-redirect-dashboard');
    const countdownElementLogout = document.getElementById('countdown-redirect-logout');
    
    

    if (countdownElementLogin){
        redirectLoginCountdown();
    }
    if (countdownElementDashboard) {
        redirectDashboardCountdown();
    }
        if (countdownElementLogout){
        redirectLogoutCountdown();
    }
});

let redirectTimerLoginInterval = null;
let redirectTimerDashboardInterval = null;
let redirectTimerLogoutInterval = null;

function redirectLogoutCountdown(){
    const countdownElementLogout = document.getElementById('countdown-redirect-logout');
    console.log("Started the process redirectTimerLogoutInterval");
    if (redirectTimerLogoutInterval) {
        clearInterval(redirectTimerLogoutInterval);
    }

    let timeLeft = 5;

    redirectTimerLogoutInterval = setInterval(function () {
        timeLeft -= 1;
        countdownElementLogout.textContent = timeLeft;

        if (timeLeft <=0) {
            clearInterval(redirectTimerLogoutInterval);
            window.location.href = '/';
            
        }
    }, 1000);

}



function redirectLoginCountdown(){
    const countdownElementLogin = document.getElementById('countdown-redirect-login');
    const countdownElementLoginDiv = document.getElementById('timeout-div');
    console.log("Started the process redirectLogingCountdown");
    if (redirectTimerLoginInterval) {
        clearInterval(redirectTimerLoginInterval);
        fetch('/refresh_session');
    }

    let timeLeft = 60;

    redirectTimerLoginInterval = setInterval(function () {
        timeLeft -= 1;
        countdownElementLogin.textContent = timeLeft;
        if (timeLeft >=11){
            countdownElementLoginDiv.style.display = 'none'
        }

        if (timeLeft <=10) {
            countdownElementLoginDiv.style.display = 'block';
        }

        if (timeLeft <=0) {
            clearInterval(redirectTimerLoginInterval);
            window.location.href = '/';
        }
    }, 1000);

}

function redirectDashboardCountdown(){
    const countdownElementDashboard = document.getElementById('countdown-redirect-dashboard');
    console.log("Started the process redirectLogingCountdown");
    if (redirectTimerDashboardInterval) {
        clearInterval(redirectTimerDashboardInterval);
    }

    let timeLeft = 10;

    redirectTimerDashboardInterval = setInterval(function () {
        timeLeft -= 1;
        countdownElementDashboard.textContent = timeLeft;

        if (timeLeft <=0) {
            clearInterval(redirectTimerDashboardInterval);
            window.location.href = '/dashboard';
            
        }
    }, 1000);

}
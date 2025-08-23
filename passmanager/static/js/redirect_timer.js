document.addEventListener('DOMContentLoaded', function() {
    const countdownElementLogin = document.getElementById('countdown-redirect-login');
    const countdownElementDashboard = document.getElementById('countdown-redirect-dashboard');

    if (countdownElementLogin){
        redirectLoginCountdown();
    }
    if (countdownElementDashboard) {
        redirectDashboardCountdown();
    }
});

let redirectTimerLoginInterval = null;
let redirectTimerDashboardInterval = null;

function redirectLoginCountdown(){
    const countdownElementLogin = document.getElementById('countdown-redirect-login');
    const countdownElementLoginDiv = document.getElementById('timeout-div');

    if (redirectTimerLoginInterval) {
        clearInterval(redirectTimerLoginInterval);
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
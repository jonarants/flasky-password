console.log('Session manager script is running.');
const sessionTimeout = 60;
const timeoutInMilliseconds = sessionTimeout * 1000;
let inactivityTimer;

function resetTimer(eventSource = 'Initial Call') {
        console.log(`Timer reset by: ${eventSource}`);
        clearTimeout(inactivityTimer);
        inactivityTimer = setTimeout(() => {
            alert('Your session is about to expire. The page will now refresh.');
            window.location.reload(); // Force a page refresh
        }, timeoutInMilliseconds);
    }

document.addEventListener('DOMContentLoaded', resetTimer);
document.addEventListener('mousemove', resetTimer);
document.addEventListener('keypress', resetTimer);
document.addEventListener('scroll', resetTimer);
document.addEventListener('click', resetTimer);

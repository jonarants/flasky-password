document.addEventListener('DOMContentLoaded', function() {
    const twofacheckbox = document.getElementById('twofacheckbox');

    
    

    if (twofacheckbox){
        this.addEventListener('change', display2FA)
    }
});

//let redirectTimerLoginInterval = null;

function display2FA(){
    const twofatoken = document.getElementById('twofatoken');
    const twofacheckbox = document.getElementById('twofacheckbox');
    console.log("Checking for checkbox");

    if (twofacheckbox.checked) {
        console.log('Checkbox is checked')
        twofatoken.style.display = 'inline';
    } else {
        console.log('Checkbox is unchecked')
        twofatoken.style.display = 'none';
    }

}
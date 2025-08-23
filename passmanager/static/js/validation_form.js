document.addEventListener('DOMContentLoaded', function() {
    const formulary = document.getElementById('validate_qr');

    if (formulary){
        formulary.addEventListener('submit', function(event){
            const user = document.getElementById('user_id').textContent.trim();

            const userHiddenFIeld = document.getElementById('user_hidden');
            userHiddenFIeld.value = user;
        });
    }
});
// sidebar.js

// Live customer search functionality
function filterCustomers() {
    const input = document.getElementById('customerSearch');
    if (!input) return;
    
    const filter = input.value.toLowerCase();
    const list = document.getElementById('customerList');
    if (!list) return;
    
    const items = list.getElementsByClassName('customer-item');

    for (let i = 0; i < items.length; i++) {
        const txt = items[i].textContent || items[i].innerText;
        if (txt.toLowerCase().includes(filter)) {
            items[i].style.display = "";
        } else {
            items[i].style.display = "none";
        }
    }
}

// In case we want to attach event listener dynamically instead of onkeyup in HTML
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('customerSearch');
    if (searchInput) {
        searchInput.addEventListener('keyup', filterCustomers);
    }
});

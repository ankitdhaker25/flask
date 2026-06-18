// dropdown.js

document.addEventListener('DOMContentLoaded', () => {
    const profileToggle = document.getElementById("profileToggle");
    const dropdownMenu = document.getElementById("dropdownMenu");

    if (profileToggle && dropdownMenu) {
        // Toggle dropdown on profile click
        profileToggle.addEventListener("click", () => {
            dropdownMenu.classList.toggle("show");
        });

        // Close dropdown when clicking outside
        window.addEventListener("click", function(e) {
            if (!profileToggle.contains(e.target) && !dropdownMenu.contains(e.target)) {
                dropdownMenu.classList.remove("show");
            }
        });
    }
});

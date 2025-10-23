(function () {
    [...document.querySelectorAll(".control")].forEach(button => {
        button.addEventListener("click", function() {
            document.querySelector(".active-btn").classList.remove("active-btn");
            this.classList.add("active-btn");
            document.querySelector(".active").classList.remove("active");
            document.getElementById(button.dataset.id).classList.add("active");
        })
    });
    document.querySelector(".theme-btn").addEventListener("click", () => {
        document.body.classList.toggle("light-mode");
    })
})();



// alert message when user leave site 
// unsaved=true;
// window.onbeforeunload = function() { 
//     if (unsaved) 
//     { 
//         var _message = "Matt ja bhai...!"; 
//         return _message; 
//     } 
// }
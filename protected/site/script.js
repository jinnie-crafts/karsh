const spyder = document.getElementById("spyder");
const lines = ["Game Developer", "App Developer", "Web Developer"];
let i = 0, j = 0, isDeleting = false;
let speed = 120;

function typeEffect() {
  const current = lines[i];

  if (!isDeleting && j < current.length) {
    spyder.textContent = current.substring(0, j + 1);
    j++;
  } else if (isDeleting && j > 0) {
    spyder.textContent = current.substring(0, j - 1);
    j--;
  } else if (!isDeleting && j === current.length) {
    isDeleting = true;
    setTimeout(typeEffect, 1000); // pause before deleting
    return;
  } else if (isDeleting && j === 0) {
    isDeleting = false;
    i = (i + 1) % lines.length;
  }

  setTimeout(typeEffect, isDeleting ? speed / 1.8 : speed);
}

typeEffect();

// // alert message when user leave site 
// unsaved=true;
// window.onbeforeunload = function() { 
//     if (unsaved) 
//     { 
//         var _message = "Matt ja bhai...!"; 
//         return _message; 
//     } 
// }

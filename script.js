// GSAP Animations
gsap.from(".grid-item", {
  duration: 2,
  opacity: 0,
  y: 25,
  stagger: 0.5,
  ease: "expo.out"
});

// Responsive menu toggle
const menuToggle = document.getElementById("menu-toggle");
const mobileMenu = document.getElementById("mobile-menu");

if (menuToggle && mobileMenu) {
  menuToggle.addEventListener("click", () => {
    mobileMenu.classList.toggle("hidden");
  });
}
// Lắng nghe sự kiện di chuyển chuột (mouse move)
document.querySelectorAll('ul li').forEach(item => {
  item.addEventListener('mousemove', (event) => {
    const rect = item.getBoundingClientRect();
    const offsetX = event.clientX - rect.left;  // Vị trí chuột trong phần tử
    const offsetY = event.clientY - rect.top;   // Vị trí chuột trong phần tử

    // Tính toán góc và dịch chuyển
    const moveX = (offsetX / rect.width) * 20 - 10;  // Tính độ dịch chuyển theo chiều X
    const moveY = (offsetY / rect.height) * 20 - 10; // Tính độ dịch chuyển theo chiều Y

    // Thực hiện hiệu ứng dịch chuyển ngược lại
    item.style.transform = `translate(${moveX}px, ${moveY}px)`;
  });

  // Khi chuột rời khỏi phần tử, khôi phục lại vị trí ban đầu
  item.addEventListener('mouseleave', () => {
    item.style.transform = 'translate(0, 0)';
  });
});



// nhac
// Lấy các phần tử cần thiết
const icon = document.getElementById("clickable-icon");
const audio = document.getElementById("audio");

// Thiết lập âm lượng nhạc nhỏ
audio.volume = 0.4; // Giảm âm lượng xuống 10%

// Thêm sự kiện click vào icon
icon.addEventListener("click", function () {
  // Kiểm tra xem nhạc có đang phát không
  if (audio.paused) {
    // Nếu nhạc chưa phát, phát nhạc và thêm hiệu ứng quay cho icon
    audio.play();
    icon.classList.add("rotate");
  } else {
    // Nếu nhạc đang phát, dừng nhạc và dừng quay
    audio.pause();
    icon.classList.remove("rotate");
  }
});

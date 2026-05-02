# 📂 PHP FILEMANAGER GOLD (PHP File Manager)

A powerful, modern, and highly optimized single-file PHP file manager. 

Drop a single `filemanager.php` into any directory on your server to instantly get a premium file management interface. It features a mobile-responsive UI, a built-in code editor with undo/redo, bulk operations, and a Local Version Control System (LVCS).

![PHP Version](https://img.shields.io/badge/PHP-%E2%89%A5%207.2-777BB4.svg?logo=php&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-brightgreen.svg)

## ✨ Features

*   **Single-File Drop-in:** No complex installations, databases, or npm packages. Just one PHP file.
*   **Advanced Code Editor:** Built-in editor featuring line numbers, font scaling, find & replace, native `Ctrl+S` saving, and undo/redo (`Ctrl+Z`).
*   **Local Version Control (LVCS):** Automatically backs up older versions of text files when you edit them. Seamlessly pull and push previous versions if you make a mistake.
*   **Smart Bulk Actions:** Multi-select files to Copy, Move, Zip, or Delete. Includes collision detection (Skip, Auto-Rename, Overwrite) when moving files.
*   **Archive Management:** Native AES-256 encrypted ZIP creation and extraction without requiring server command-line access.
*   **Mobile-First UI:** A beautiful, responsive interface that works perfectly on phones, tablets, and desktops.
*   **Security Built-in:** CSRF protection, Path Traversal locking, and strict HTML escaping to prevent XSS.

## 🚀 Quick Start

1. Download `filemanager.php`.
2. Open the file in a text editor and change the default password at the top of the file:
   ```php
   $PASSWORD = 'CHANGE_THIS_TO_A_STRONG_PASSWORD';

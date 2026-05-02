<?php
// filemanager.php - v3.6
// Single-file PHP File Manager: Security Hardened, UI Polished, Pro Tools
// -------------------------------------------------------------------
// CONFIGURATION
// -------------------------------------------------------------------
$PASSWORD = '👀_what_are_you_looking_for?';           // <<< CHANGE THIS IMMEDIATELY
$BASE_DIR = realpath(__DIR__);    // Manage this folder and below
$ALLOW_DELETE = true;             // Allow delete actions
$UPLOAD_LIMIT_MB = 100;           // Server upload limit request
$MAX_EDIT_SIZE_MB = 2;            // Max size for text editor to prevent browser crash
$LVCS_DIR_NAME = '.lvcs';         // Name of the hidden git folder

// Try to override server limits
@ini_set('upload_max_filesize', $UPLOAD_LIMIT_MB . 'M');
@ini_set('post_max_size', ($UPLOAD_LIMIT_MB + 10) . 'M');
@ini_set('memory_limit', '256M');

session_start();
$TIMEZONE = @date_default_timezone_get() ?: 'UTC';
@date_default_timezone_set($TIMEZONE);

// -------------------------------------------------------------------
// CORE HELPERS & UTILS
// -------------------------------------------------------------------
if (!isset($_SESSION['fm_started'])) $_SESSION['fm_started'] = time();
if (time() - $_SESSION['fm_started'] > (3 * 3600)) {
    unset($_SESSION['undo_stack']); unset($_SESSION['redo_stack']);
    $_SESSION['fm_started'] = time();
}
if (!isset($_SESSION['undo_stack'])) $_SESSION['undo_stack'] = [];
if (!isset($_SESSION['redo_stack'])) $_SESSION['redo_stack'] = [];

function json_response($data, $status = 200) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

function require_auth() {
    if (empty($_SESSION['fm_auth']) || $_SESSION['fm_auth'] !== true) json_response(['error' => 'Not authenticated'], 401);
}

function get_rel_path($p) {
    if ($p === null) return '';
    $p = trim(str_replace(['\\', "\0"], ['/', ''], (string)$p));
    $p = preg_replace('#/+#', '/', $p);
    $p = ltrim($p, '/');
    if ($p === '.' || $p === '') return '';
    if (strpos($p, '..') !== false) return false;
    return $p;
}

function get_full_path($rel) {
    global $BASE_DIR;
    $s = get_rel_path($rel);
    if ($s === false) return false;
    $full = $BASE_DIR . ($s === '' ? '' : '/' . $s);
    if (strpos($full, $BASE_DIR) !== 0) return false;
    return $full;
}

function rrmdir($dir) {
    if (!is_dir($dir)) return;
    $items = array_diff(scandir($dir), ['.', '..']);
    foreach ($items as $item) {
        $path = $dir . '/' . $item;
        is_dir($path) ? rrmdir($path) : @unlink($path);
    }
    @rmdir($dir);
}

function rcopy($src, $dst) {
    if (is_dir($src)) {
        @mkdir($dst, 0755, true);
        $files = scandir($src);
        foreach ($files as $file) {
            if ($file != "." && $file != "..") rcopy("$src/$file", "$dst/$file");
        }
    } else if (file_exists($src)) {
        @copy($src, $dst);
    }
}

function is_text_file($path) {
    if (!is_file($path)) return false;
    $fh = @fopen($path, 'rb');
    if ($fh) {
        $chunk = fread($fh, 512);
        fclose($fh);
        if (strpos($chunk, "\0") === false) return true;
    }
    return false;
}

// -------------------------------------------------------------------
// PHP ZIPPER CLASS
// -------------------------------------------------------------------
class PhpZipper {
    public static function compressItems($sources, $destination, $password = null) {
        if (!extension_loaded('zip')) throw new Exception("PHP zip extension missing.");
        $zip = new ZipArchive();
        if ($zip->open($destination, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) throw new Exception("Failed to create ZIP.");

        foreach ($sources as $source) {
            if (!file_exists($source)) continue;
            $basename = basename($source);
            
            if (is_dir($source)) {
                $iterator = new RecursiveDirectoryIterator($source, RecursiveDirectoryIterator::SKIP_DOTS);
                $files = new RecursiveIteratorIterator($iterator, RecursiveIteratorIterator::SELF_FIRST);
                $zip->addEmptyDir($basename);

                foreach ($files as $file) {
                    $fileReal = $file->getRealPath();
                    $relativePath = $basename . '/' . str_replace('\\', '/', substr($fileReal, strlen($source) + 1));
                    if ($file->isDir()) {
                        $zip->addEmptyDir($relativePath);
                    } else if ($file->isFile()) {
                        $zip->addFile($fileReal, $relativePath);
                        if ($password) $zip->setEncryptionName($relativePath, ZipArchive::EM_AES_256, $password);
                    }
                }
            } else if (is_file($source)) {
                $zip->addFile($source, $basename);
                if ($password) $zip->setEncryptionName($basename, ZipArchive::EM_AES_256, $password);
            }
        }
        $zip->close();
        return true;
    }

    public static function extract($source, $destination, $password = null) {
        if (!extension_loaded('zip')) throw new Exception("PHP zip extension missing.");
        $zip = new ZipArchive();
        if ($zip->open($source) !== true) throw new Exception("Failed to open ZIP.");
        if ($password) $zip->setPassword($password);
        if (!$zip->extractTo($destination)) {
            $zip->close();
            throw new Exception("Extraction failed. Invalid password?");
        }
        $zip->close();
        return true;
    }
}

// -------------------------------------------------------------------
// API HANDLERS
// -------------------------------------------------------------------
$action = $_REQUEST['action'] ?? '';

if ($action === 'login') {
    $pw = $_POST['password'] ?? '';
    if ($pw === $PASSWORD) {
        $_SESSION['fm_auth'] = true;
        $_SESSION['fm_csrf'] = bin2hex(random_bytes(16));
        json_response(['success' => true, 'csrf' => $_SESSION['fm_csrf']]);
    }
    json_response(['error' => 'Invalid password'], 403);
}

if ($action === 'logout') {
    unset($_SESSION['fm_auth']);
    json_response(['success' => true]);
}

if ($action) require_auth();

if ($action === 'list') {
    $p = $_GET['path'] ?? '';
    $full = get_full_path($p);
    if ($full === false || !is_dir($full)) { $p = ''; $full = $BASE_DIR; }

    $items = scandir($full);
    $entries = [];
    foreach ($items as $name) {
        if ($name === '.' || $name === '..') continue;
        if ($name === $LVCS_DIR_NAME) continue;
        $f = $full . '/' . $name;
        $is_dir = is_dir($f);
        $entries[] = [
            'name' => $name, 'path' => ($p === '' ? $name : $p . '/' . $name),
            'is_dir' => $is_dir, 'size' => $is_dir ? count(scandir($f)) - 2 : filesize($f),
            'mtime' => filemtime($f), 'ext' => pathinfo($name, PATHINFO_EXTENSION)
        ];
    }
    usort($entries, function($a, $b) {
        if ($a['is_dir'] !== $b['is_dir']) return $b['is_dir'] <=> $a['is_dir'];
        return strcasecmp($a['name'], $b['name']);
    });
    json_response(['path' => $p, 'entries' => $entries]);
}

if ($action === 'mkdir') {
    $full = get_full_path($_POST['path'] ?? '');
    if ($full && !file_exists($full) && @mkdir($full, 0755, true)) json_response(['success' => true]);
    json_response(['error' => 'Failed to create directory'], 500);
}

if ($action === 'create_file') {
    $full = get_full_path($_POST['path'] ?? '');
    if ($full && !file_exists($full) && @file_put_contents($full, '') !== false) json_response(['success' => true]);
    json_response(['error' => 'Failed to create file'], 500);
}

if ($action === 'read') {
    $full = get_full_path($_GET['path'] ?? '');
    if (!$full || !is_file($full)) json_response(['error' => 'File not found'], 404);
    if (!is_text_file($full)) json_response(['error' => 'Binary file'], 400);
    if (filesize($full) > ($MAX_EDIT_SIZE_MB * 1024 * 1024)) json_response(['error' => "File exceeds {$MAX_EDIT_SIZE_MB}MB limit"], 400);
    json_response(['content' => file_get_contents($full)]);
}

if ($action === 'save') {
    if (!hash_equals($_SESSION['fm_csrf'] ?? '', $_POST['csrf'] ?? '')) json_response(['error' => 'CSRF error'], 403);
    $p = $_POST['path'] ?? ''; $full = get_full_path($p);
    if (!$full || !is_file($full)) json_response(['error' => 'Not found'], 404);

    $current = file_get_contents($full);
    if (!isset($_SESSION['undo_stack'][$p])) $_SESSION['undo_stack'][$p] = [];
    array_push($_SESSION['undo_stack'][$p], $current);
    if (count($_SESSION['undo_stack'][$p]) > 10) array_shift($_SESSION['undo_stack'][$p]);
    $_SESSION['redo_stack'][$p] = [];

    if (@file_put_contents($full, $_POST['content'] ?? '') !== false) json_response(['success' => true]);
    json_response(['error' => 'Save failed'], 500);
}

if (in_array($action, ['undo', 'redo'])) {
    $p = $_POST['path'] ?? ''; $full = get_full_path($p);
    if (!$full || !is_file($full)) json_response(['error' => 'File not found'], 404);
    
    $from = $action === 'undo' ? 'undo_stack' : 'redo_stack';
    $to = $action === 'undo' ? 'redo_stack' : 'undo_stack';

    if (empty($_SESSION[$from][$p])) json_response(['error' => "Nothing to $action", 'empty' => true], 200);
    $new_content = array_pop($_SESSION[$from][$p]);
    if (!isset($_SESSION[$to][$p])) $_SESSION[$to][$p] = [];
    array_push($_SESSION[$to][$p], file_get_contents($full));
    
    file_put_contents($full, $new_content);
    json_response(['success' => true, 'content' => $new_content]);
}

// --- LVCS Backend Logic ---
if ($action === 'lvcs_push') {
    if (!hash_equals($_SESSION['fm_csrf'] ?? '', $_POST['csrf'] ?? '')) json_response(['error' => 'CSRF error'], 403);
    $p = $_POST['path'] ?? ''; $full = get_full_path($p);
    if (!$full || !is_file($full)) json_response(['error' => 'File not found'], 404);

    $content = $_POST['content'] ?? '';
    file_put_contents($full, $content); 

    $dir = dirname($full); $filename = basename($full);
    $lvcs_root = $dir . '/' . $LVCS_DIR_NAME . '/' . $filename;
    if (!is_dir($lvcs_root)) @mkdir($lvcs_root, 0777, true);

    $timestamp = time();
    if (@file_put_contents($lvcs_root . '/' . $timestamp . '.txt', $content) !== false) {
        json_response(['success' => true, 'ts' => $timestamp]);
    }
    json_response(['error' => 'Push failed'], 500);
}

if ($action === 'lvcs_list') {
    $p = $_GET['path'] ?? ''; $full = get_full_path($p);
    if (!$full) json_response(['error' => 'File not found'], 404);

    $lvcs_root = dirname($full) . '/' . $LVCS_DIR_NAME . '/' . basename($full);
    $versions = [];
    if (is_dir($lvcs_root)) {
        foreach (scandir($lvcs_root) as $f) {
            if ($f === '.' || $f === '..') continue;
            if (pathinfo($f, PATHINFO_EXTENSION) === 'txt') {
                $ts = pathinfo($f, PATHINFO_FILENAME);
                $versions[] = ['ts' => $ts, 'date' => date('Y-m-d H:i:s', (int)$ts), 'size' => filesize($lvcs_root . '/' . $f)];
            }
        }
    }
    usort($versions, function($a, $b) { return $b['ts'] <=> $a['ts']; }); // Newest first
    json_response(['versions' => $versions]);
}

if ($action === 'lvcs_pull') {
    if (!hash_equals($_SESSION['fm_csrf'] ?? '', $_POST['csrf'] ?? '')) json_response(['error' => 'CSRF error'], 403);
    $p = $_POST['path'] ?? ''; $ts = $_POST['ts'] ?? ''; $full = get_full_path($p);
    if (!$full) json_response(['error' => 'File not found'], 404);

    $lvcs_file = dirname($full) . '/' . $LVCS_DIR_NAME . '/' . basename($full) . '/' . $ts . '.txt';
    if (!file_exists($lvcs_file)) json_response(['error' => 'Version not found'], 404);

    $content = file_get_contents($lvcs_file);
    file_put_contents($full, $content); 
    
    if (!isset($_SESSION['undo_stack'][$p])) $_SESSION['undo_stack'][$p] = [];
    array_push($_SESSION['undo_stack'][$p], $content); 

    json_response(['success' => true, 'content' => $content]);
}

if ($action === 'rename') {
    if (!hash_equals($_SESSION['fm_csrf'] ?? '', $_POST['csrf'] ?? '')) json_response(['error' => 'CSRF'], 403);
    $oldf = get_full_path($_POST['old'] ?? ''); $newf = get_full_path($_POST['new'] ?? '');
    if ($oldf && $newf && @rename($oldf, $newf)) json_response(['success' => true]);
    json_response(['error' => 'Rename failed'], 500);
}

if ($action === 'check_collisions') {
    if (!hash_equals($_SESSION['fm_csrf'] ?? '', $_POST['csrf'] ?? '')) json_response(['error' => 'CSRF'], 403);
    $paths = json_decode($_POST['paths'] ?? '[]', true);
    $dest = get_full_path($_POST['dest'] ?? '');
    $collisions = [];
    foreach ($paths as $p) {
        $target = $dest . '/' . basename($p);
        if (file_exists($target)) $collisions[] = basename($p);
    }
    json_response(['collisions' => $collisions]);
}

if ($action === 'bulk_action') {
    if (!hash_equals($_SESSION['fm_csrf'] ?? '', $_POST['csrf'] ?? '')) json_response(['error' => 'CSRF'], 403);
    $type = $_POST['type'] ?? '';
    $paths = json_decode($_POST['paths'] ?? '[]', true);
    $dest = get_full_path($_POST['dest'] ?? '');
    $strategy = $_POST['strategy'] ?? 'skip'; 
    
    if (empty($paths) || !is_array($paths)) json_response(['error' => 'No items selected'], 400);

    foreach ($paths as $p) {
        $full = get_full_path($p);
        if (!$full || !file_exists($full)) continue;
        
        $base = basename($full);
        $target = $dest . '/' . $base;

        if ($type !== 'delete' && file_exists($target) && $full !== $target) {
            if ($strategy === 'skip') continue;
            if ($strategy === 'rename') {
                $info = pathinfo($base);
                $name = $info['filename'];
                $ext = isset($info['extension']) ? '.' . $info['extension'] : '';
                $i = 1;
                while (file_exists($dest . '/' . $name . " ($i)" . $ext)) $i++;
                $target = $dest . '/' . $name . " ($i)" . $ext;
            }
            if ($strategy === 'overwrite' && $ALLOW_DELETE) {
                is_dir($target) ? rrmdir($target) : @unlink($target);
            }
        }

        if ($type === 'delete' && $ALLOW_DELETE) {
            is_dir($full) ? rrmdir($full) : @unlink($full);
        } else if ($type === 'copy' && $dest) {
            if ($full !== $target) rcopy($full, $target);
        } else if ($type === 'move' && $dest) {
            if ($full !== $target) @rename($full, $target);
        }
    }
    json_response(['success' => true]);
}

if ($action === 'zip_bulk') {
    if (!hash_equals($_SESSION['fm_csrf'] ?? '', $_POST['csrf'] ?? '')) json_response(['error' => 'CSRF'], 403);
    $paths = json_decode($_POST['paths'] ?? '[]', true);
    $dest = get_full_path($_POST['dest'] ?? '');
    $zipname = $_POST['zipname'] ?? 'archive.zip';
    $password = !empty($_POST['password']) ? $_POST['password'] : null;
    $delete_orig = (!empty($_POST['delete_orig']) && $_POST['delete_orig'] === 'true');

    if (empty($paths) || !$dest) json_response(['error' => 'Invalid parameters'], 400);
    $full_paths = array_filter(array_map('get_full_path', $paths));
    
    try {
        PhpZipper::compressItems($full_paths, $dest . '/' . $zipname, $password);
        if ($delete_orig && $ALLOW_DELETE) {
            foreach ($full_paths as $p) { is_dir($p) ? rrmdir($p) : @unlink($p); }
        }
        json_response(['success' => true]);
    } catch (Exception $e) { json_response(['error' => $e->getMessage()], 500); }
}

if ($action === 'unzip') {
    if (!hash_equals($_SESSION['fm_csrf'] ?? '', $_POST['csrf'] ?? '')) json_response(['error' => 'CSRF'], 403);
    $zipfile = get_full_path($_POST['path'] ?? '');
    $dest = get_full_path($_POST['dest'] ?? '');
    $password = !empty($_POST['password']) ? $_POST['password'] : null;
    $in_place = (!empty($_POST['in_place']) && $_POST['in_place'] === 'true');
    $delete_zip = (!empty($_POST['delete_zip']) && $_POST['delete_zip'] === 'true');

    if (!$zipfile || !$dest || !is_file($zipfile)) json_response(['error' => 'Invalid file'], 400);
    
    $extract_dir = $in_place ? $dest : $dest . '/' . pathinfo($zipfile, PATHINFO_FILENAME);
    if (!$in_place && !is_dir($extract_dir)) @mkdir($extract_dir, 0755, true);

    try {
        PhpZipper::extract($zipfile, $extract_dir, $password);
        if ($delete_zip && $ALLOW_DELETE) @unlink($zipfile);
        json_response(['success' => true, 'extracted_to' => basename($extract_dir)]);
    } catch (Exception $e) { 
        if (!$in_place) @rmdir($extract_dir);
        json_response(['error' => $e->getMessage()], 500); 
    }
}

if ($action === 'download') {
    $full = get_full_path($_GET['path'] ?? '');
    if (!$full || !is_file($full)) die('File not found');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="'.basename($full).'"');
    header('Content-Length: '.filesize($full));
    readfile($full); exit;
}

if ($action === 'upload') {
    if (!hash_equals($_SESSION['fm_csrf'] ?? '', $_POST['csrf'] ?? '')) json_response(['error' => 'CSRF'], 403);
    $full_dir = get_full_path($_POST['dir'] ?? '');
    if (!$full_dir || !is_dir($full_dir)) json_response(['error' => 'Invalid dir'], 400);
    if (empty($_FILES['file'])) json_response(['error' => "No file"], 400);
    $f = $_FILES['file'];
    if (move_uploaded_file($f['tmp_name'], $full_dir . '/' . basename($f['name']))) json_response(['success' => true]);
    json_response(['error' => 'Move failed'], 500);
}

// -------------------------------------------------------------------
// HTML & UI
// -------------------------------------------------------------------
$csrf = $_SESSION['fm_csrf'] ?? '';
$root_name = basename($BASE_DIR);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>FM: <?php echo htmlspecialchars($root_name); ?></title>
<style>
/* Modern CSS Reset & Vars */
:root {
    --bg: #f8fafc; --sidebar: #1e293b; --sidebar-txt: #94a3b8;
    --accent: #6366f1; --accent-hover: #4f46e5;
    --text: #334155; --border: #e2e8f0; --white: #ffffff;
    --danger: #ef4444; --success: #22c55e;
}
@media (prefers-color-scheme: dark) {
    :root {
        --bg: #0f172a; --sidebar: #020617; --sidebar-txt: #64748b;
        --accent: #818cf8; --accent-hover: #6366f1;
        --text: #cbd5e1; --border: #1e293b; --white: #1e293b;
    }
}
* { box-sizing: border-box; outline: none; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: var(--bg); color: var(--text); height: 100vh; display: flex; overflow: hidden; }

/* Layout */
.sidebar { width: 240px; background: var(--sidebar); color: var(--sidebar-txt); display: flex; flex-direction: column; padding: 20px; flex-shrink: 0; }
.main { flex: 1; display: flex; flex-direction: column; overflow: hidden; position: relative; }
.brand { font-size: 18px; font-weight: bold; color: #fff; margin-bottom: 30px; display: flex; align-items: center; gap: 10px; }

/* Headers & Tools */
.main-header { padding: 20px 25px; background: var(--white); border-bottom: 1px solid var(--border); display: flex; flex-direction: column; gap: 15px; }
.path-title { font-size: 22px; font-weight: 600; color: var(--text); display: flex; align-items: center; gap: 10px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.path-title span { color: var(--accent); cursor: pointer; }
.path-title span:hover { text-decoration: underline; }

.toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.btn { padding: 8px 14px; border-radius: 6px; border: 1px solid var(--border); background: var(--white); color: var(--text); cursor: pointer; font-size: 13px; font-weight: 500; transition: 0.1s; display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; }
.btn:hover { background: var(--bg); border-color: var(--accent); color: var(--accent); }
.btn.primary { background: var(--accent); color: #fff; border: 0; }
.btn.primary:hover { background: var(--accent-hover); }

/* File List */
.file-area { flex: 1; overflow-y: auto; padding: 0 25px 80px 25px; }
.list-table { width: 100%; border-collapse: collapse; font-size: 14px; }
.list-table th { text-align: left; padding: 15px 10px; color: var(--sidebar-txt); font-weight: 600; border-bottom: 2px solid var(--border); position: sticky; top: 0; background: var(--bg); z-index: 5; }
.list-table td { padding: 12px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
.list-table tr:hover td { background: rgba(99, 102, 241, 0.05); }

.cb-cell { width: 40px; text-align: center; }
.item-cb { width: 16px; height: 16px; cursor: pointer; accent-color: var(--accent); }

.name-cell { display: flex; flex-direction: column; justify-content: center; cursor: pointer; }
.name-text { font-weight: 500; display: flex; align-items: center; gap: 8px; color: var(--text); word-break: break-all;}
.meta-text { font-size: 11px; color: var(--sidebar-txt); margin-top: 4px; margin-left: 26px; }

.mobile-only { display: none; } 

.file-icon { font-size: 18px; }
.actions { display: flex; gap: 4px; justify-content: flex-end; opacity: 0.3; transition: 0.2s; }
.list-table tr:hover .actions { opacity: 1; }

/* Modals */
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 99; display: none; align-items: center; justify-content: center; backdrop-filter: blur(2px); }
.modal { background: var(--white); padding: 20px; border-radius: 12px; width: 400px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); max-width: 95%; }
.modal h3 { margin: 0 0 15px 0; font-size: 18px; }
.modal input.text-input { width: 100%; padding: 10px; border: 1px solid var(--border); border-radius: 6px; background: var(--bg); color: var(--text); margin-bottom: 15px; }
.modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 15px;}

/* Editor */
.editor-modal { width: 95vw; height: 95vh; display: flex; flex-direction: column; max-width: none; }
.editor-toolbar { padding: 0 0 10px 0; border-bottom: 1px solid var(--border); display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.editor-wrapper { display: flex; flex: 1; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; background: #1e1e1e; }
.line-numbers { padding: 15px 10px; background: #2d2d2d; color: #858585; font-family: 'Consolas', monospace; font-size: 14px; text-align: right; user-select: none; border-right: 1px solid #444; overflow: hidden; line-height: 1.5; min-width: 45px; }
.editor-textarea { flex: 1; background: transparent; color: #d4d4d4; font-family: 'Consolas', monospace; font-size: 14px; padding: 15px; border: 0; resize: none; line-height: 1.5; outline: none; white-space: pre; overflow: auto; }
.editor-input { padding: 6px 10px; border: 1px solid var(--border); border-radius: 4px; font-size: 13px; width: 120px; background: var(--bg); color: var(--text); }
.find-replace-bar { display: none; padding: 10px 0; border-bottom: 1px solid var(--border); margin-bottom: 10px; gap: 8px; align-items: center; flex-wrap: wrap; }

/* Floating Bars */
.floating-bar { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%) translateY(150%); background: var(--sidebar); color: #fff; padding: 12px 25px; border-radius: 50px; display: flex; align-items: center; gap: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.3); z-index: 100; transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275); width: max-content; max-width: 95vw; flex-wrap: wrap; justify-content: center; }
.floating-bar.visible { transform: translateX(-50%) translateY(0); }
.floating-bar .btn { background: rgba(255,255,255,0.1); border: 0; color: #fff; }
.floating-bar .btn:hover { background: rgba(255,255,255,0.2); }

.toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 1000; display: flex; flex-direction: column; gap: 10px; }
.toast { background: var(--sidebar); color: #fff; padding: 12px 20px; border-radius: 6px; font-size: 14px; animation: slideIn 0.3s ease; }
@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

/* Utility Classes */
.hidden { display: none !important; }

/* Mobile Optimizations */
@media (max-width: 768px) {
    .sidebar { display: none; }
    .main-header { padding: 15px 15px 10px 15px; }
    .path-title { font-size: 18px; }
    .toolbar { gap: 6px; }
    .btn { padding: 6px 10px; font-size: 12px; }
    
    .file-area { padding: 0 15px 80px 15px; }
    .hide-mobile { display: none !important; }
    .mobile-only { display: block !important; }
    .actions { opacity: 1; }

    .editor-modal { width: 100vw; height: 100vh; border-radius: 0; }
    .editor-input { width: 75px; }
    .modal { padding: 15px; }
    
    .floating-bar { border-radius: 12px; bottom: 10px; padding: 10px; }
}
</style>
</head>
<body>

<div id="login-overlay" class="modal-overlay" style="display: flex;">
    <div class="modal">
        <h3>🔒 Login</h3>
        <input type="password" class="text-input" id="password-input" placeholder="Enter password..." onkeyup="if(event.key==='Enter') doLogin()">
        <button class="btn primary" style="width:100%" onclick="doLogin()">Unlock</button>
    </div>
</div>

<div class="sidebar">
    <div class="brand">📂 FileManager</div>
    <button class="btn primary" onclick="openUpload()" style="justify-content:center; margin-bottom:20px">☁ Upload Files</button>
    <div style="flex:1"></div>
    <div style="font-size:12px; opacity:0.5">v3.6 - Hardened & Polished</div>
</div>

<div class="main" id="drop-zone">
    <div class="main-header">
        <div class="path-title" id="path-title">🏠 /</div>
        <div class="toolbar">
            <button class="btn" onclick="loadPath(parentPath)">⬅ <span class="hide-mobile">Up</span></button>
            <button class="btn" onclick="loadPath(currentPath)">⟳ <span class="hide-mobile">Refresh</span></button>
            <button id="upload-btn" class="btn primary" onclick="openUpload()">☁ <span class="hide-mobile">Upload</span></button>
            <button class="btn" onclick="promptMkdir()">+ Folder</button>
            <button class="btn" onclick="promptNewFile()">+ File</button>
            <div style="flex:1"></div>
            <button class="btn" onclick="doLogout()">Logout</button>
        </div>
    </div>

    <div class="file-area">
        <table class="list-table">
            <thead>
                <tr>
                    <th class="cb-cell"><input type="checkbox" id="cb-all" class="item-cb" onclick="toggleAll()"></th>
                    <th>Name</th>
                    <th class="hide-mobile">Size</th>
                    <th class="hide-mobile">Date Modified</th>
                    <th style="text-align:right">Actions</th>
                </tr>
            </thead>
            <tbody id="file-list"></tbody>
        </table>
    </div>
</div>

<!-- Floating Bulk Bar -->
<div id="bulk-bar" class="floating-bar">
    <span id="bulk-count" style="font-weight:bold; margin-right:5px;">0 selected</span>
    <button class="btn" onclick="triggerClipboard('copy')">📋 <span class="hide-mobile">Copy</span></button>
    <button class="btn" onclick="triggerClipboard('move')">✂ <span class="hide-mobile">Move</span></button>
    <button class="btn" onclick="promptZipBulk()">📦 <span class="hide-mobile">Zip</span></button>
    <button class="btn" style="color:#ff8a8a" onclick="bulkDelete()">🗑 <span class="hide-mobile">Delete</span></button>
    <button class="btn" style="background:transparent; padding:0" onclick="clearSelection()">✕</button>
</div>

<!-- Floating Clipboard Paste Bar -->
<div id="paste-bar" class="floating-bar" style="background: var(--accent);">
    <span id="paste-info" style="font-weight:bold; margin-right:5px;">Clipboard</span>
    <button class="btn" style="background:#fff; color:var(--accent); font-weight:bold" onclick="pasteClipboard()">📥 Paste Here</button>
    <button class="btn" style="background:transparent; padding:0" onclick="clearClipboard()">✕</button>
</div>

<div id="ui-modal" class="modal-overlay">
    <div class="modal" id="ui-modal-content"></div>
</div>

<div class="toast-container" id="toasts"></div>
<input type="file" id="upload-input" multiple class="hidden" onchange="processUploads(this.files)">

<script>
let currentPath = ''; let parentPath = '';
let csrfToken = '<?php echo $csrf; ?>';
let isAuthenticated = <?php echo isset($_SESSION['fm_auth']) ? 'true' : 'false'; ?>;

let selectedItems = new Set();
let clipboard = { action: null, items: [] };

// Editor State
let currentEditFile = '';
let editorFontSize = 14;
let editorSearch = { matches: [], current: -1, text: '' };

document.addEventListener('DOMContentLoaded', () => {
    if(!isAuthenticated) document.getElementById('login-overlay').style.display = 'flex';
    else { document.getElementById('login-overlay').style.display = 'none'; loadPath(''); }
});

// XSS Protection Helper
function escapeHTML(str) {
    return str.replace(/[&<>'"]/g, tag => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
    }[tag]));
}

// --- GLOBAL KEYBOARD SHORTCUTS ---
document.addEventListener('keydown', e => {
    // Escape closes modals
    if (e.key === 'Escape') {
        closeModal();
        const pullModal = document.getElementById('pull-modal');
        if (pullModal) pullModal.remove();
    }
    
    // Ctrl+S saves active editor file natively
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        const editorContent = document.getElementById('editor-content');
        if (editorContent && editorContent.offsetParent !== null && currentEditFile) {
            e.preventDefault();
            saveFile(currentEditFile);
        }
    }
});

async function api(action, data = {}) {
    const formData = new FormData();
    formData.append('action', action); formData.append('csrf', csrfToken);
    for (const key in data) formData.append(key, data[key]);
    try {
        const r = await fetch('?', { method: 'POST', body: formData });
        const res = await r.json();
        if (res.error) throw res.error;
        return res;
    } catch (e) { toast(e, 'error'); throw e; }
}

async function doLogin() {
    try {
        const res = await api('login', { password: document.getElementById('password-input').value });
        if(res.success) { isAuthenticated = true; csrfToken = res.csrf; document.getElementById('login-overlay').style.display = 'none'; loadPath(''); }
    } catch(e) {}
}

async function doLogout() { await api('logout'); location.reload(); }

async function loadPath(path) {
    try {
        const res = await fetch(`?action=list&path=${encodeURIComponent(path)}`).then(r => r.json());
        if(res.error) throw res.error;
        currentPath = res.path;
        parentPath = currentPath.split('/').slice(0, -1).join('/');
        
        clearSelection();
        renderList(res.entries);
        
        const parts = currentPath ? currentPath.split('/') : [];
        let html = '<span onclick="loadPath(\'\')">🏠 ROOT</span>';
        let build = '';
        parts.forEach(p => { build += (build ? '/' : '') + p; html += ` <span style="color:var(--text); text-decoration:none">/</span> <span onclick="loadPath('${escapeHTML(build)}')">${escapeHTML(p)}</span>`; });
        document.getElementById('path-title').innerHTML = html;
        
        updateBars();
    } catch(e) { toast(e, 'error'); }
}

function renderList(entries) {
    const tbody = document.getElementById('file-list'); tbody.innerHTML = '';
    if(entries.length === 0) { tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:40px; color:var(--sidebar-txt)">Empty folder</td></tr>`; return; }

    entries.forEach(e => {
        const tr = document.createElement('tr');
        const icon = e.is_dir ? '📁' : (['png','jpg','jpeg','gif','webp','svg','ico'].includes(e.ext) ? '🖼' : (e.ext==='zip'?'📦':'📄'));
        const sizeStr = e.is_dir ? e.size + ' items' : formatSize(e.size);
        const dateStr = new Date(e.mtime * 1000).toLocaleString();
        
        const safePath = escapeHTML(e.path);
        const safeName = escapeHTML(e.name);
        
        let actions = '';
        if(e.is_dir) actions += `<button class="btn" onclick="loadPath('${safePath}')">➡ <span class="hide-mobile">Open</span></button>`;
        else {
            if (e.ext === 'zip') actions += `<button class="btn primary" onclick="promptUnzip('${safePath}')">📦 <span class="hide-mobile">Unzip</span></button>`;
            actions += `<button class="btn" onclick="editFile('${safePath}')">✏ <span class="hide-mobile">Edit</span></button>`;
            actions += `<button class="btn" onclick="downloadFile('${safePath}')">⬇ <span class="hide-mobile">DL</span></button>`;
        }
        actions += `<button class="btn" onclick="promptRename('${safePath}', '${safeName}')">Aa</button>`;
        
        const clickAction = e.is_dir ? `loadPath('${safePath}')` : `editFile('${safePath}')`;

        tr.innerHTML = `
            <td class="cb-cell"><input type="checkbox" class="item-cb" value="${safePath}" onchange="toggleItem(this)"></td>
            <td>
                <div class="name-cell" onclick="${clickAction}">
                    <div class="name-text"><span class="file-icon">${icon}</span> <span style="word-break: break-all;">${safeName}</span></div>
                    <div class="meta-text mobile-only">${sizeStr} &nbsp;&bull;&nbsp; ${dateStr}</div>
                </div>
            </td>
            <td class="hide-mobile">${sizeStr}</td>
            <td class="hide-mobile">${dateStr}</td>
            <td class="actions">${actions}</td>
        `;
        tbody.appendChild(tr);
    });
}

// --- BULK / CHECKBOX LOGIC ---
function toggleItem(cb) {
    if(cb.checked) selectedItems.add(cb.value); else selectedItems.delete(cb.value);
    updateBars();
}
function toggleAll() {
    const master = document.getElementById('cb-all');
    const cbs = document.querySelectorAll('.item-cb');
    if(master.checked) cbs.forEach(cb => { cb.checked = true; selectedItems.add(cb.value); });
    else { cbs.forEach(cb => cb.checked = false); selectedItems.clear(); }
    updateBars();
}
function clearSelection() {
    selectedItems.clear(); document.getElementById('cb-all').checked = false;
    document.querySelectorAll('.item-cb').forEach(cb => cb.checked = false); updateBars();
}
function triggerClipboard(action) {
    clipboard = { action: action, items: Array.from(selectedItems) }; clearSelection();
    toast(`Saved ${clipboard.items.length} items for ${action}`);
}
function clearClipboard() { clipboard = { action: null, items: [] }; updateBars(); }

function updateBars() {
    const bulkBar = document.getElementById('bulk-bar'); const pasteBar = document.getElementById('paste-bar');
    if (selectedItems.size > 0) { document.getElementById('bulk-count').innerText = `${selectedItems.size} selected`; bulkBar.classList.add('visible'); } 
    else bulkBar.classList.remove('visible');
    if (clipboard.items.length > 0 && selectedItems.size === 0) { document.getElementById('paste-info').innerText = `${clipboard.action.toUpperCase()} ${clipboard.items.length} items ready`; pasteBar.classList.add('visible'); } 
    else pasteBar.classList.remove('visible');
}

async function bulkDelete() {
    if(!confirm(`Permanently delete ${selectedItems.size} items?`)) return;
    try { await api('bulk_action', { type: 'delete', paths: JSON.stringify(Array.from(selectedItems)) }); toast('Deleted items'); loadPath(currentPath); } catch(e) {}
}

async function pasteClipboard() {
    if(clipboard.items.length === 0) return;
    
    try {
        const check = await api('check_collisions', { paths: JSON.stringify(clipboard.items), dest: currentPath });
        if(check.collisions && check.collisions.length > 0) {
            let names = check.collisions.slice(0, 3).map(escapeHTML).join(', ');
            if (check.collisions.length > 3) names += ' and ' + (check.collisions.length - 3) + ' more';
            
            showModal('File Conflict', `
                <p style="font-size:14px; margin-bottom:15px; line-height:1.5">The following files already exist in this folder:<br><b>${names}</b></p>
                <p style="font-size:13px; color:var(--sidebar-txt); margin-bottom:15px">How do you want to handle this?</p>
                <div class="modal-actions">
                    <button class="btn" onclick="closeModal()">Cancel</button>
                    <button class="btn" onclick="executePaste('skip')">Skip Existing</button>
                    <button class="btn" onclick="executePaste('rename')">Auto-Rename</button>
                    <button class="btn primary" style="background:var(--danger)" onclick="executePaste('overwrite')">Overwrite All</button>
                </div>
            `);
            return;
        }
    } catch(e) { return; }

    executePaste('overwrite');
}

async function executePaste(strategy) {
    if(document.getElementById('ui-modal').style.display === 'flex') closeModal();
    toast(`Processing ${clipboard.action}...`);
    try { 
        await api('bulk_action', { type: clipboard.action, paths: JSON.stringify(clipboard.items), dest: currentPath, strategy }); 
        toast('Paste complete!'); clearClipboard(); loadPath(currentPath); 
    } catch(e) {}
}

// --- ZIP LOGIC ---
function promptZipBulk() { 
    showModal('Zip Selected', `
        <input id="zip-name" class="text-input" value="archive.zip">
        <input id="zip-pass" class="text-input" type="password" placeholder="Password (Optional)">
        <div style="margin-bottom:10px">
            <label style="font-size:14px; cursor:pointer"><input type="checkbox" id="zip-del-orig"> Delete original items after zipping</label>
        </div>
        <div class="modal-actions"><button class="btn" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="execZipBulk()">Zip</button></div>
    `, false, '', true); 
}
async function execZipBulk() {
    const zipname = document.getElementById('zip-name').value; const password = document.getElementById('zip-pass').value;
    const delOrig = document.getElementById('zip-del-orig').checked;
    if(!zipname) return;
    try { toast('Zipping...'); await api('zip_bulk', { paths: JSON.stringify(Array.from(selectedItems)), dest: currentPath, zipname, password, delete_orig: delOrig }); closeModal(); clearSelection(); loadPath(currentPath); toast('Archive created!'); } catch(e) {}
}

function promptUnzip(path) { 
    showModal('Extract Archive', `
        <p style="font-size:14px; margin-bottom:15px; color:var(--sidebar-txt); word-break:break-all;">${path}</p>
        <input id="unzip-pass" class="text-input" type="password" placeholder="Password (Leave blank if none)">
        <div style="margin-bottom:10px; display:flex; flex-direction:column; gap:8px;">
            <label style="font-size:14px; cursor:pointer"><input type="checkbox" id="unzip-in-place"> Extract directly into current folder</label>
            <label style="font-size:14px; cursor:pointer"><input type="checkbox" id="unzip-del-zip"> Delete ZIP file after extracting</label>
        </div>
        <div class="modal-actions"><button class="btn" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="execUnzip('${path}')">Extract</button></div>
    `, false, '', true); 
}
async function execUnzip(path) {
    const password = document.getElementById('unzip-pass').value;
    const inPlace = document.getElementById('unzip-in-place').checked;
    const delZip = document.getElementById('unzip-del-zip').checked;
    try { toast('Extracting...'); const res = await api('unzip', { path, dest: currentPath, password, in_place: inPlace, delete_zip: delZip }); closeModal(); loadPath(currentPath); toast(`Extracted successfully!`); } catch(e) {}
}

// --- CREATION & RENAMING ---
function promptMkdir() { showModal('New Folder', `<input id="new-folder-name" class="text-input" placeholder="Folder Name"><div class="modal-actions"><button class="btn" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="createFolder()">Create</button></div>`, false, '', true); }
async function createFolder() { const name = document.getElementById('new-folder-name').value; if(!name) return; try { await api('mkdir', { path: currentPath ? currentPath + '/' + name : name }); closeModal(); loadPath(currentPath); } catch(e){} }
function promptNewFile() { showModal('New File', `<input id="new-file-name" class="text-input" placeholder="filename.txt"><div class="modal-actions"><button class="btn" onclick="closeModal()">Cancel</button><button class="btn primary" onclick="createFile()">Create</button></div>`, false, '', true); }
async function createFile() { const name = document.getElementById('new-file-name').value; if(!name) return; const target = currentPath ? currentPath + '/' + name : name; try { await api('create_file', { path: target }); closeModal(); loadPath(currentPath); editFile(target); } catch(e){} }

function promptRename(path, oldName) { 
    showModal('Rename Item', `
        <input id="rename-input" class="text-input" value="${oldName}">
        <div class="modal-actions">
            <button class="btn" onclick="closeModal()">Cancel</button>
            <button class="btn primary" onclick="execRename('${path}', '${oldName}')">Rename</button>
        </div>
    `, false, '', true); 
}
async function execRename(path, oldName) {
    const newName = document.getElementById('rename-input').value;
    if(newName && newName !== oldName) {
        const dir = path.substring(0, path.lastIndexOf('/'));
        const target = dir ? dir + '/' + newName : newName;
        try { await api('rename', { old: path, new: target }); closeModal(); loadPath(currentPath); toast('Renamed'); } catch(e){}
    } else { closeModal(); }
}

// --- EDITOR ENHANCEMENTS & LVCS ---
async function editFile(path) {
    currentEditFile = path;
    const ext = path.split('.').pop().toLowerCase();
    if(['jpg','jpeg','png','gif','webp','svg','ico'].includes(ext)) { showModal('Preview', `<div style="text-align:center"><img src="?action=download&path=${encodeURIComponent(path)}" style="max-width:100%; max-height:60vh; border-radius:8px"></div>`, true); return; }
    try {
        const res = await fetch(`?action=read&path=${encodeURIComponent(path)}`).then(r => r.json());
        if(res.error) throw res.error;
        showModal(`Editing: ${escapeHTML(path.split('/').pop())}`, `
            <div class="editor-toolbar">
                <button class="btn" onclick="undoEdit()" title="Undo">↩</button>
                <button class="btn" onclick="redoEdit()" title="Redo">↪</button>
                <div style="width:1px; height:20px; background:var(--border); margin:0 2px;"></div>
                <button class="btn" onclick="toggleFindReplace()">🔍 <span class="hide-mobile">Find</span></button>
                
                <div style="flex:1"></div>
                
                <button class="btn" style="border-color:var(--accent); color:var(--accent)" onclick="lvcsPull()" title="Pull Version">↓ <span class="hide-mobile">Pull</span></button>
                <button class="btn" style="background:var(--accent); color:#fff; border:0" onclick="lvcsPush()" title="Push Version">↑ <span class="hide-mobile">Push</span></button>
                
                <div style="width:1px; height:20px; background:var(--border); margin:0 2px;"></div>
                
                <button class="btn" onclick="changeFontSize(-1)">A-</button>
                <button class="btn" onclick="changeFontSize(1)">A+</button>
            </div>
            <div id="find-replace-bar" class="find-replace-bar">
                <input id="find-text" class="editor-input" placeholder="Find..." oninput="doSearch()" onkeyup="if(event.key==='Enter') navMatch(1)">
                <span id="match-count" style="font-size:12px; color:var(--sidebar-txt); min-width:35px; text-align:center">0/0</span>
                <button class="btn" onclick="navMatch(-1)">←</button>
                <button class="btn" onclick="navMatch(1)">→</button>
                <div style="width:1px; height:20px; background:var(--border); margin:0 5px;"></div>
                <input id="replace-text" class="editor-input" placeholder="Replace with...">
                <button class="btn" onclick="replaceCurrent()">Replace</button>
                <button class="btn" onclick="replaceAll()">Replace All</button>
            </div>
            <div class="editor-wrapper" style="margin-bottom:15px">
                <div id="line-numbers" class="line-numbers">1</div>
                <textarea id="editor-content" class="editor-textarea" spellcheck="false" oninput="updateLineNumbers()" onscroll="syncScroll()"></textarea>
            </div>
            <div class="modal-actions" style="margin-top:0">
                <button class="btn" onclick="closeModal()">Close</button>
                <button class="btn primary" onclick="saveFile('${path}')">Save <span style="font-size:10px; opacity:0.7">(Ctrl+S)</span></button>
            </div>
        `, false, 'editor-modal');
        
        const editorContent = document.getElementById('editor-content');
        editorContent.value = res.content;
        
        // Handle Tab Key for Code Editing
        editorContent.addEventListener('keydown', function(e) {
            if (e.key === 'Tab') {
                e.preventDefault();
                // Use execCommand to preserve browser undo history if available
                if (!document.execCommand('insertText', false, '    ')) {
                    // Fallback
                    const start = this.selectionStart;
                    const end = this.selectionEnd;
                    this.value = this.value.substring(0, start) + "    " + this.value.substring(end);
                    this.selectionStart = this.selectionEnd = start + 4;
                }
                updateLineNumbers();
            }
        });

        applyFontSize();
        updateLineNumbers();
        // Reset search state
        editorSearch = { matches: [], current: -1, text: '' };
    } catch(e) { toast(e, 'error'); }
}

// --- LVCS FRONTEND FUNCTIONS ---
async function lvcsPush() {
    const content = document.getElementById('editor-content').value;
    try { await api('lvcs_push', { path: currentEditFile, content }); toast('Version Pushed to GIT'); } catch(e) {}
}

async function lvcsPull() {
    try {
        const res = await fetch(`?action=lvcs_list&path=${encodeURIComponent(currentEditFile)}`).then(r=>r.json());
        if(res.error) throw res.error;
        if(res.versions.length === 0) { toast('No backup versions found', 'error'); return; }

        let listHtml = '<div style="display:flex; flex-direction:column; gap:6px; max-height:250px; overflow-y:auto; padding-right:5px">';
        res.versions.forEach(v => {
            listHtml += `
                <div style="padding:10px; border:1px solid var(--border); border-radius:6px; cursor:pointer; display:flex; justify-content:space-between" 
                     onclick="confirmPull('${v.ts}')" onmouseover="this.style.background='var(--bg)'" onmouseout="this.style.background=''">
                    <span>${v.date}</span>
                    <span style="color:var(--sidebar-txt); font-size:12px">${formatSize(v.size)}</span>
                </div>
            `;
        });
        listHtml += '</div>';

        const d = document.createElement('div');
        d.id = 'pull-modal';
        d.style.cssText = "position:fixed; inset:0; background:rgba(0,0,0,0.6); z-index:110; display:flex; align-items:center; justify-content:center; backdrop-filter:blur(2px)";
        d.innerHTML = `
            <div class="modal">
                <h3>Select Backup Version</h3>
                ${listHtml}
                <div class="modal-actions" style="margin-top:15px">
                    <button class="btn" onclick="document.getElementById('pull-modal').remove()">Cancel</button>
                </div>
            </div>
        `;
        document.getElementById('ui-modal-content').appendChild(d);
    } catch(e) { toast(e, 'error'); }
}

async function confirmPull(ts) {
    if(!confirm('Load this version? Current unsaved changes will be lost.')) return;
    try {
        const res = await api('lvcs_pull', { path: currentEditFile, ts });
        document.getElementById('editor-content').value = res.content;
        updateLineNumbers();
        document.getElementById('pull-modal').remove();
        toast('Version Loaded');
    } catch(e) {}
}

// --- EDITOR FIND/REPLACE & UTILS ---
function updateLineNumbers() {
    const txt = document.getElementById('editor-content').value;
    const lines = txt.split('\n').length;
    document.getElementById('line-numbers').innerHTML = Array.from({length: lines || 1}, (_, i) => i + 1).join('<br>');
}

function syncScroll() { document.getElementById('line-numbers').scrollTop = document.getElementById('editor-content').scrollTop; }

function changeFontSize(diff) {
    editorFontSize += (diff * 2);
    if(editorFontSize < 8) editorFontSize = 8;
    if(editorFontSize > 36) editorFontSize = 36;
    applyFontSize();
}

function applyFontSize() {
    document.getElementById('editor-content').style.fontSize = editorFontSize + 'px';
    document.getElementById('line-numbers').style.fontSize = editorFontSize + 'px';
}

function toggleFindReplace() {
    const bar = document.getElementById('find-replace-bar');
    bar.style.display = bar.style.display === 'flex' ? 'none' : 'flex';
    if(bar.style.display === 'flex') document.getElementById('find-text').focus();
}

function doSearch() {
    const f = document.getElementById('find-text').value;
    const el = document.getElementById('editor-content');
    const txt = el.value;
    editorSearch.matches = [];
    editorSearch.current = -1;
    editorSearch.text = f;
    
    if (!f) { updateSearchUI(); return; }

    let idx = txt.indexOf(f);
    while (idx !== -1) {
        editorSearch.matches.push(idx);
        idx = txt.indexOf(f, idx + f.length);
    }
    
    if (editorSearch.matches.length > 0) {
        editorSearch.current = 0;
        highlightMatch();
    }
    updateSearchUI();
}

function navMatch(dir) {
    if(editorSearch.matches.length === 0) return;
    editorSearch.current += dir;
    if(editorSearch.current < 0) editorSearch.current = editorSearch.matches.length - 1;
    if(editorSearch.current >= editorSearch.matches.length) editorSearch.current = 0;
    highlightMatch();
    updateSearchUI();
}

function highlightMatch() {
    const el = document.getElementById('editor-content');
    if(editorSearch.current >= 0 && editorSearch.matches.length > 0) {
        const start = editorSearch.matches[editorSearch.current];
        el.focus();
        el.setSelectionRange(start, start + editorSearch.text.length);
        
        const lines = el.value.substr(0, start).split('\n').length;
        el.scrollTop = (lines - 2) * parseFloat(getComputedStyle(el).lineHeight);
        syncScroll();
    }
}

function updateSearchUI() {
    const c = document.getElementById('match-count');
    if(editorSearch.matches.length === 0) c.innerText = '0/0';
    else c.innerText = `${editorSearch.current + 1}/${editorSearch.matches.length}`;
}

function replaceCurrent() {
    if(editorSearch.current < 0 || editorSearch.matches.length === 0) return;
    const r = document.getElementById('replace-text').value;
    const el = document.getElementById('editor-content');
    const start = editorSearch.matches[editorSearch.current];
    const end = start + editorSearch.text.length;
    
    if (typeof el.setRangeText === 'function') {
        el.setRangeText(r, start, end, 'end');
    } else {
        el.value = el.value.substring(0, start) + r + el.value.substring(end);
    }
    
    updateLineNumbers();
    
    const oldCurrent = editorSearch.current;
    doSearch();
    if(editorSearch.matches.length > 0) {
        editorSearch.current = oldCurrent >= editorSearch.matches.length ? editorSearch.matches.length - 1 : oldCurrent;
        highlightMatch();
        updateSearchUI();
    }
}

function replaceAll() {
    const f = document.getElementById('find-text').value;
    const r = document.getElementById('replace-text').value;
    if(!f) return;
    const el = document.getElementById('editor-content');
    
    if(!document.execCommand('insertText', false, el.value.split(f).join(r))) {
        el.value = el.value.split(f).join(r);
    }
    
    updateLineNumbers();
    doSearch();
    toast('Replaced all occurrences');
}

async function saveFile(path) { try { await api('save', { path, content: document.getElementById('editor-content').value }); toast('Saved'); } catch(e){} }
async function undoEdit() { try { const r = await api('undo', { path: currentEditFile }); if(!r.error){ document.getElementById('editor-content').value = r.content; updateLineNumbers(); toast('Undone'); doSearch(); } } catch(e){} }
async function redoEdit() { try { const r = await api('redo', { path: currentEditFile }); if(!r.error){ document.getElementById('editor-content').value = r.content; updateLineNumbers(); toast('Redone'); doSearch(); } } catch(e){} }

// --- UPLOAD & MISC ---
function downloadFile(path) { window.location.href = `?action=download&path=${encodeURIComponent(path)}`; }
function openUpload() { document.getElementById('upload-input').click(); }
async function processUploads(files) {
    if(!files.length) return; 
    
    const uploadBtn = document.getElementById('upload-btn');
    const originalText = uploadBtn.innerHTML;
    uploadBtn.innerHTML = '⏳ Uploading...';
    toast(`Uploading ${files.length} files...`);
    
    for (const file of files) {
        const fd = new FormData(); fd.append('action', 'upload'); fd.append('file', file); fd.append('dir', currentPath); fd.append('csrf', csrfToken);
        try { await fetch('?', { method: 'POST', body: fd }); } catch(e) {}
    }
    
    uploadBtn.innerHTML = originalText;
    loadPath(currentPath); toast('Uploads complete'); document.getElementById('upload-input').value = '';
}
const dz = document.getElementById('drop-zone');
dz.addEventListener('dragover', e => { e.preventDefault(); dz.style.background = 'rgba(99,102,241,0.05)'; });
dz.addEventListener('dragleave', e => { e.preventDefault(); dz.style.background = ''; });
dz.addEventListener('drop', e => { e.preventDefault(); dz.style.background = ''; processUploads(e.dataTransfer.files); });

function showModal(title, html, autoClose=false, extClass='', focus=false) {
    const c = document.getElementById('ui-modal-content');
    c.className = 'modal ' + extClass; c.innerHTML = `<h3>${title}</h3>${html}`;
    document.getElementById('ui-modal').style.display = 'flex';
    if(autoClose) c.innerHTML += `<div class="modal-actions"><button class="btn" onclick="closeModal()">Close</button></div>`;
    if(focus) setTimeout(()=> { const inp = c.querySelector('input'); if(inp) inp.focus(); }, 100);
}
function closeModal() { 
    document.getElementById('ui-modal').style.display = 'none'; 
    currentEditFile = ''; 
}
function formatSize(b) { if(b===0)return'0 B'; const k=1024, s=['B','KB','MB','GB','TB'], i=Math.floor(Math.log(b)/Math.log(k)); return parseFloat((b/Math.pow(k,i)).toFixed(2))+' '+s[i]; }
function toast(msg, type='success') {
    const t = document.createElement('div'); t.className = 'toast'; t.style.borderLeft = `4px solid ${type==='error'?'var(--danger)':'var(--success)'}`; t.innerHTML = msg;
    document.getElementById('toasts').appendChild(t); setTimeout(() => t.remove(), 3000);
}
</script>
</body>
</html>

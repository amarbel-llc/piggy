;;; piggy.el --- PIV password store support  -*- lexical-binding: t; -*-

;; Copyright (C) 2014-2019 Svend Sorensen <svend@svends.net>

;; Author: Svend Sorensen <svend@svends.net>
;; Maintainer: Tino Calancha <tino.calancha@gmail.com>
;; Version: 0.1.0
;; URL: https://github.com/amarbel-llc/piggy
;; Package-Requires: ((emacs "26.1") (with-editor "2.5.11"))
;; SPDX-License-Identifier: GPL-3.0-or-later
;; Keywords: tools piggy password pivy

;; This file is not part of GNU Emacs.

;; This program is free software: you can redistribute it and/or
;; modify it under the terms of the GNU General Public License as
;; published by the Free Software Foundation, either version 3 of
;; the License, or (at your option) any later version.

;; This program is distributed in the hope that it will be
;; useful, but WITHOUT ANY WARRANTY; without even the implied
;; warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
;; PURPOSE.  See the GNU General Public License for more details.

;; You should have received a copy of the GNU General Public
;; License along with this program.  If not, see
;; <http://www.gnu.org/licenses/>.

;;; Commentary:

;; This package provides an Emacs interface for working with
;; piggy, a PIV-based password store using pivy-box and ebox templates.

;;; Code:

(require 'with-editor)

(defgroup piggy '()
  "Emacs mode for piggy.
A PIV-based password store."
  :prefix "piggy-"
  :group 'piggy)

(defcustom piggy-password-length 25
  "Default password length."
  :group 'piggy
  :type 'number)

(defcustom piggy-time-before-clipboard-restore
  (if (getenv "PIGGY_CLIP_TIME")
      (string-to-number (getenv "PIGGY_CLIP_TIME"))
    45)
  "Number of seconds to wait before restoring the clipboard."
  :group 'piggy
  :type 'number)

(defcustom piggy-url-field "url"
  "Field name used in the files to indicate a URL."
  :group 'piggy
  :type 'string)

(defvar piggy-executable
  (executable-find "piggy")
  "Piggy executable.")

(defvar piggy-timeout-timer nil
  "Timer for clearing clipboard.")

(defun piggy--run-1 (callback &rest args)
  "Run piggy with ARGS.

Nil arguments are ignored.  Calls CALLBACK with the output on
success, or outputs error message on failure."
  (let ((output ""))
    (make-process
     :name "piggy"
     :command (cons piggy-executable (delq nil args))
     :connection-type 'pipe
     :noquery t
     :filter (lambda (process text)
               (setq output (concat output text)))
     :sentinel (lambda (process state)
                 (cond
                  ((and (eq (process-status process) 'exit)
                        (zerop (process-exit-status process)))
                   (funcall callback output))
                  ((eq (process-status process) 'run) (accept-process-output process))
                  (t (error (concat "piggy: " state))))))))

(defun piggy--run (&rest args)
  "Run piggy with ARGS.

Nil arguments are ignored.  Returns the output on success, or
outputs error message on failure."
  (let ((output nil))
    (apply #'piggy--run-1 (lambda (password)
                                     (setq output password))
           (delq nil args))
    (while (not output)
      (sleep-for .1))
    output))

(defun piggy--run-async (&rest args)
  "Run piggy asynchronously with ARGS.

Nil arguments are ignored.  Output is discarded."
  (let ((args (mapcar #'shell-quote-argument args)))
    (with-editor-async-shell-command
     (mapconcat 'identity
                (cons piggy-executable
                      (delq nil args)) " "))))

(defun piggy--run-show (entry &optional callback)
  (if callback
      (piggy--run-1 callback "pass" "show" entry)
    (piggy--run "pass" "show" entry)))

(defun piggy--run-edit (entry)
  (piggy--run-async "pass" "edit"
                             entry))

(defun piggy--run-generate (entry password-length &optional force no-symbols)
  (piggy--run "pass" "generate"
                       (if force "--force")
                       (if no-symbols "--no-symbols")
                       entry
                       (number-to-string password-length)))

(defun piggy--run-remove (entry &optional recursive)
  (piggy--run "pass" "remove"
                       "--force"
                       (if recursive "--recursive")
                       entry))

(defun piggy--run-rename (entry new-entry &optional force)
  (piggy--run "pass" "rename"
                       (if force "--force")
                       entry
                       new-entry))

(defun piggy--run-copy (entry new-entry &optional force)
  (piggy--run "pass" "copy"
                       (if force "--force")
                       entry
                       new-entry))

(defun piggy--run-git (&rest args)
  (apply 'piggy--run "pass" "git"
         args))

(defun piggy--run-version ()
  (piggy--run "version"))

(defvar piggy-kill-ring-pointer nil
  "The tail of of the kill ring ring whose car is the password.")

(defun piggy-dir ()
  "Return password store directory."
  (or (getenv "PIGGY_STORE_DIR")
      (expand-file-name "piggy" (or (getenv "XDG_DATA_HOME")
                                    (expand-file-name ".local/share" (getenv "HOME"))))))

(defun piggy--entry-to-file (entry)
  "Return file name corresponding to ENTRY."
  (concat (expand-file-name entry (piggy-dir)) ".ebox"))

(defun piggy--file-to-entry (file)
  "Return entry name corresponding to FILE."
  (file-name-sans-extension (file-relative-name file (piggy-dir))))

(defun piggy--completing-read (&optional require-match)
  "Read a password entry in the minibuffer, with completion.

Require a matching password if `REQUIRE-MATCH' is 't'."
  (completing-read "Password entry: " (piggy-list) nil require-match))

(defun piggy--parse-fields (output)
  "Parse OUTPUT from piggy show into an alist of fields.
First line is the secret (key: `secret').  Subsequent lines of the
form KEY: VALUE become alist entries."
  (let ((lines (split-string output "\n" t))
        (result nil))
    (when lines
      (push (cons 'secret (car lines)) result)
      (dolist (line (cdr lines))
        (when (string-match "^\\([^:]+\\): *\\(.*\\)$" line)
          (push (cons (match-string 1 line) (match-string 2 line)) result))))
    (nreverse result)))

(defun piggy-parse-entry (entry)
  "Return an alist of the data associated with ENTRY."
  (let ((output (piggy--run "pass" "show" entry)))
    (piggy--parse-fields output)))

(defun piggy-read-field (entry)
  "Read a field in the minibuffer, with completion for ENTRY."
  (let ((valid-fields
         (let ((inhibit-message t))
           (mapcar #'car (piggy-parse-entry entry)))))
    (completing-read "Field: " valid-fields nil 'match)))

(defun piggy-list (&optional subdir)
  "List password entries under SUBDIR."
  (unless subdir (setq subdir ""))
  (let ((dir (expand-file-name subdir (piggy-dir))))
    (if (file-directory-p dir)
        (delete-dups
         (mapcar 'piggy--file-to-entry
                 (directory-files-recursively dir ".+\\.ebox\\'"))))))

;;;###autoload
(defun piggy-edit (entry)
  "Edit password for ENTRY."
  (interactive (list (piggy--completing-read t)))
  (piggy--run-edit entry))

;;;###autoload
(defun piggy-get (entry &optional callback)
  "Return password for ENTRY.

Returns the first line of the password data.  When CALLBACK is
non-`NIL', call CALLBACK with the first line instead."
  (let* ((output (piggy--run "pass" "show" entry))
         (secret (car (split-string output "\n" t))))
    (if callback
        (funcall callback secret)
      secret)))

;;;###autoload
(defun piggy-get-field (entry field &optional callback)
  "Return FIELD for ENTRY.
FIELD is a string, for instance \"url\".  When CALLBACK is
non-`NIL', call it with the line associated to FIELD instead.  If
FIELD equals to symbol secret, then this function reduces to
`piggy-get'."
  (let* ((parsed (piggy-parse-entry entry))
         (value (cdr (assoc (if (eq field 'secret) 'secret field) parsed))))
    (if callback
        (funcall callback value)
      value)))

;;;###autoload
(defun piggy-clear (&optional field)
  "Clear secret in the kill ring.

Optional argument FIELD, a symbol or a string, describes the
stored secret to clear; if nil, then set it to \\='secret."
  (interactive "i")
  (unless field (setq field 'secret))
  (when piggy-timeout-timer
    (cancel-timer piggy-timeout-timer)
    (setq piggy-timeout-timer nil))
  (when piggy-kill-ring-pointer
    (setcar piggy-kill-ring-pointer "")
    (kill-new "")
    (setq piggy-kill-ring-pointer nil)
    (message "Field %s cleared from kill ring and system clipboard." field)))

(defun piggy--save-field-in-kill-ring (entry secret field)
  (piggy-clear field)
  (kill-new secret)
  (setq piggy-kill-ring-pointer kill-ring-yank-pointer)
  (message "Copied %s for %s to the kill ring and system clipboard. Will clear in %s seconds."
           field entry piggy-time-before-clipboard-restore)
  (setq piggy-timeout-timer
        (run-at-time piggy-time-before-clipboard-restore nil
                     (lambda () (funcall #'piggy-clear field)))))

;;;###autoload
(defun piggy-copy (entry)
  "Add password for ENTRY into the kill ring.

Clear previous password from the kill ring.  Pointer to the kill
ring is stored in `piggy-kill-ring-pointer'.  Password
is cleared after `piggy-time-before-clipboard-restore'
seconds."
  (interactive (list (piggy--completing-read t)))
  (piggy-get
   entry
   (lambda (password)
     (piggy--save-field-in-kill-ring entry password 'secret))))

;;;###autoload
(defun piggy-copy-field (entry field)
  "Add FIELD for ENTRY into the kill ring.

Clear previous secret from the kill ring.  Pointer to the kill
ring is stored in `piggy-kill-ring-pointer'.  Secret
field is cleared after
`piggy-time-before-clipboard-restore' seconds.  If FIELD
equals to symbol secret, then this function reduces to
`piggy-copy'."
  (interactive
   (let ((entry (piggy--completing-read)))
     (list entry (piggy-read-field entry))))
  (piggy-get-field
   entry
   field
   (lambda (secret-value)
     (piggy--save-field-in-kill-ring entry secret-value field))))

;;;###autoload
(defun piggy-insert (entry password)
  "Insert a new ENTRY containing PASSWORD."
  (interactive (list (piggy--completing-read)
                     (read-passwd "Password: " t)))
  (let* ((command (format "echo %s | %s pass insert -m -f %s"
                          (shell-quote-argument password)
                          piggy-executable
                          (shell-quote-argument entry)))
         (ret (process-file-shell-command command)))
    (if (zerop ret)
        (message "Successfully inserted entry for %s" entry)
      (message "Cannot insert entry for %s" entry))
    nil))

;;;###autoload
(defun piggy-generate (entry &optional password-length)
  "Generate a new password for ENTRY with PASSWORD-LENGTH.

Default PASSWORD-LENGTH is `piggy-password-length'."
  (interactive (list (piggy--completing-read)
                     (and current-prefix-arg
                          (abs (prefix-numeric-value current-prefix-arg)))))
  (piggy--run-generate
   entry
   (or password-length piggy-password-length)
   'force)
  nil)

;;;###autoload
(defun piggy-generate-no-symbols (entry &optional password-length)
  "Generate a new password without symbols for ENTRY with PASSWORD-LENGTH.

Default PASSWORD-LENGTH is `piggy-password-length'."
  (interactive (list (piggy--completing-read)
                     (and current-prefix-arg
                          (abs (prefix-numeric-value current-prefix-arg)))))
  (piggy--run-generate
   entry
   (or password-length piggy-password-length)
   'force 'no-symbols)
  nil)

;;;###autoload
(defun piggy-remove (entry)
  "Remove ENTRY."
  (interactive (list (piggy--completing-read t)))
  (message "%s" (piggy--run-remove entry t)))

;;;###autoload
(defun piggy-rename (entry new-entry)
  "Rename ENTRY to NEW-ENTRY."
  (interactive (list (piggy--completing-read t)
                     (read-string "Rename entry to: ")))
  (message "%s" (piggy--run-rename entry new-entry t)))

;;;###autoload
(defun piggy-version ()
  "Show version of `piggy-executable'."
  (interactive)
  (message "%s" (piggy--run-version)))

;;;###autoload
(defun piggy-url (entry)
  "Load URL for ENTRY."
  (interactive (list (piggy--completing-read t)))
  (let ((url (piggy-get-field entry piggy-url-field)))
    (if url (browse-url url)
      (error "Field `%s' not found" piggy-url-field))))


(provide 'piggy)

;;; piggy.el ends here

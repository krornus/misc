; nnoremap <F5> :!(clear; sbcl --script %)<CR>

(defun println (s &optional (out *standard-output*))
  (format out "~a~%" s))

; ###########
; Problem 1
; ###########

(defun prob1 (n &optional (cur 1) (s 0))
  (if (< cur n)
    (if (or (eq 0 (mod cur 3)) (eq 0 (mod cur 5)))
      (prob1 n (1+ cur) (+ s cur))
      (prob1 n (1+ cur) s))
    s))


(defun prob1-test ()
  (and (eq 233168 (prob1 1000)) (eq 23 (prob1 10))))


; ###########
; Problem 2
; ###########

(defun fibonacci (
    n
    &optional
    (fcn (lambda (seq elmt) (append seq (list elmt))))
    (s ())
    (a 0)
    (b 1))
  (if (> a n)
    s
    (fibonacci n fcn (funcall fcn s a) b (+ a b))))


(defun prob2-test () (
  eq 4613732 (fibonacci 4000000 (
    lambda (s a) (
      if (zerop (mod a 2)) (+ s a) s))
    0 0 1)))


; ###########
; Problem 3
; ###########

(defun factor (n &optional (div 2) (fct ()))
    (if (> div (truncate n 2))
      (cons n fct) ; div greater halfway point, add current factor
      (if (zerop (mod n div)) ; found a divisor
        (factor (truncate n div) 2 (cons div fct)) ; recurse with quotient, add divisor to list
        (factor n (1+ div) fct)))) ; increment divisor, recurse


(defun prob3-test ()
  (eq 6857 (car (sort (factor 600851475143) '>))))


; ###########
; Problem 4
; ###########

(defun prob4 (m &optional (a m) (b m) (pdms ()))
  (if (zerop b)
    pdms
    (let ((pal (princ-to-string (* a b))))
      (if (string= pal (reverse pal))
        (if (eq 1 a)
          (prob4 m m (1- b) (cons (read-from-string pal) pdms))
          (prob4 m (1- a) b (cons (read-from-string pal) pdms)))
        (if (eq 1 a)
          (prob4 m m (1- b) pdms)
          (prob4 m (1- a) b pdms))))))

(defun prob4-test ()
  (eq 906609 (car (sort (prob4 999) '>))))


; ###########
; Problem 5
; ###########

(defun can-factor (n fact)
  (if (eq 1 fact)
    t ; init return is true
    (if (zerop (mod n fact))
      (can-factor n (1- fact)) ; returns true AND previous factor
      nil)))

(defun prob5 (n &optional (val (1+ n)))
  (if (can-factor val n)
    val
    (prob5 n (1+ val))))

(defun prob5-test ()
  (eq 232792560 (prob5 20)))


; ###########
; Problem 6
; ###########

(defun sum-of-sqr (n &optional (sum 0))
  (if (zerop n)
    sum
    (sum-of-sqr (1- n) (+ sum (* n n)))))

(defun sqr-of-sum (n &optional (sum 0))
  (if (zerop n)
    (* sum sum)
    (sqr-of-sum (1- n) (+ sum n))))

(defun prob6 (n)
  (- (sqr-of-sum n) (sum-of-sqr n)))

(defun prob6-test ()
  (eq 25164150 (prob6 100)))


; ###########
; Problem 7
; ###########

(defun prob7 (n &optional (prime -1) (ctr 3) (nprimes 1))
  (if (eq nprimes n)
    prime
    (if (equal (car (factor ctr)) ctr)
      (prob7 n ctr (+ 1 ctr) (1+ nprimes))
      (prob7 n prime (+ 1 ctr) nprimes))))

(defun prob7-test ()
  (eq 104743 (prob7 10001)))


; ###########
; Problem 8
; ###########

(defun test (fcns)
  (if (eq nil fcns)
    nil
    (progn
      (format *standard-output* "Problem ~a: ~a~%"
        (car fcns)
        (funcall
          (symbol-function (find-symbol
            (string-upcase (format nil "prob~a-test" (car fcns)))))))
      (test (cdr fcns)))))


; ###########
; Problem 9
; ###########

(defun prob8 (len)
  (with-open-file (fs "/home/spowell/programming/lisp/euler/prob8num")
    (let* ((str (read-line fs)) (strlen (length str)))
    (prob8h len str strlen 0))))

(defun prob8h (len num numlen &optional (pos 0) (mval -1) (mpos -1))
  (if (>= (+ len pos) numlen)
    (subseq num mpos (+ mpos len))
    (let ((phi (mul-str (subseq num pos (+ len pos)))))
      (if (<= mval phi)
        (prob8h len num numlen (1+ pos) phi pos)
        (prob8h len num numlen (1+ pos) mval mpos)))))


(defun mul-str (s)
  (reduce '* (map 'list #'digit-char-p (coerce s 'list)) :initial-value 1))


; ###########
; Problem 10
; ###########

(defun prob10 (n &optional (a 1) (b (- n a)) (- n (+ a b)))
  (if (= a (1- n))


(print (prob10 1000))

;(test '(1))

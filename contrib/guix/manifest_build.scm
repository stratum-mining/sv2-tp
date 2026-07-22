(use-modules (gnu packages)
             ((gnu packages bash) #:select (bash-minimal))
             ((gnu packages cmake) #:select (cmake-minimal))
             (gnu packages commencement)
             ((gnu packages compression) #:select (gzip zip))
             (gnu packages gawk)
             (gnu packages llvm)
             ((gnu packages python) #:select (python-minimal))
             ((gnu packages python-xyz) #:select (python-lief))
             ((gnu packages version-control) #:select (git-minimal))
             (guix packages)
             ((guix utils) #:select (substitute-keyword-arguments))
             (toolchains))

;; python-lief transitively pulls in packages whose tests fail when
;; building natively on riscv64.
(define (package-without-tests p)
  (package
    (inherit p)
    (arguments
     (substitute-keyword-arguments (package-arguments p)
       ((#:tests? _ #t) #f)))))

(define python-lief-no-riscv64-failing-tests
  ((package-input-rewriting/spec
    `(("python-psutil" . ,package-without-tests)
      ("python-pytest-xprocess" . ,package-without-tests)
      ("python-sh" . ,package-without-tests)))
   python-lief))

(packages->manifest
 (append
  (list ;; The Basics
        bash-minimal
        which
        coreutils-minimal
        ;; File(system) inspection
        grep
        diffutils
        findutils
        ;; File transformation
        patch
        gawk
        sed
        ;; Compression and archiving
        tar
        gzip
        ;; Build tools
        cmake-minimal
        gnu-make
        ;; Scripting
        python-minimal ;; 3.12
        ;; Git
        git-minimal
        ;; Tests
        python-lief-no-riscv64-failing-tests) ;; 0.17.6
  (let ((target (getenv "HOST")))
    (cond ((string-suffix? "-mingw32" target)
           (list gcc-toolchain-14
                 (make-mingw-pthreads-cross-toolchain target)
                 zip))
          ((string-contains target "-linux-")
           (list gcc-toolchain-14
                 (list gcc-toolchain-14 "static")))
          ((string-contains target "darwin")
           (list clang-toolchain-19
                 libcxx
                 lld-19
                 zip))
          (else '())))))

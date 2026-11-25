"""ExecuTorch Llama backend (calls the llama_main binary built by 02_build_rpi5.sh).

"""
import os, re, subprocess, threading

_LOG_RX = re.compile(r"[IDWEF]{1,2} \d{2}:\d{2}:\d{2}\.\d+ executorch:\S+\][^\n]*|Reached to the end of generation")

class ExecuTorchLlama:
    def __init__(self, llama_main, model, tokenizer, seq_len=512, threads=4, timeout=240, temperature=0.2, num_bos=None):
        self.llama_main, self.model, self.tokenizer = llama_main, model, tokenizer
        self.seq_len, self.threads, self.timeout, self.temperature = seq_len, threads, timeout, temperature
        self.num_bos = num_bos          # None = runner default; 1 = prepend <|begin_of_text|> (Llama 3 expects it)
        self._lock = threading.Lock()

    def missing(self) -> list:
        """Absolute paths of required files that do not exist (for clear start-up messages)."""
        return [os.path.abspath(p) for p in (self.llama_main, self.model, self.tokenizer) if not os.path.isfile(p)]

    def available(self) -> bool:
        return all(os.path.isfile(p) for p in (self.llama_main, self.model, self.tokenizer))

    def _command(self, prompt: str) -> list[str]:
        return [
            self.llama_main, f"--model_path={self.model}",
            f"--tokenizer_path={self.tokenizer}", f"--prompt={prompt}",
            f"--temperature={self.temperature}", f"--seq_len={self.seq_len}",
            f"--cpu_threads={self.threads}",
            *([f"--num_bos={self.num_bos}"] if self.num_bos is not None else []),
        ]

    def generate(self, prompt: str) -> str:
        with self._lock:
            out = subprocess.run(
                self._command(prompt),
                capture_output=True, text=True, timeout=self.timeout, check=False).stdout
        marker = "assistant<|end_header_id|>"
        if prompt in out:                        # the runner echoes the prompt first
            out = out.split(prompt, 1)[1]
        elif marker in out:
            out = out.rsplit(marker, 1)[1]
        out = out.split("PyTorchObserver")[0]
        out = _LOG_RX.sub("", out)               # drop runtime log lines if they ever reach stdout
        return re.sub(r"<\|.*?\|>", "", out).strip()

    def generate_stream(self, prompt: str):
        """Yield generated text as it arrives from llama_main."""
        with self._lock:
            process = subprocess.Popen(
                self._command(prompt),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            if process.stdout is None:
                raise RuntimeError("llama_main did not provide an output stream")

            timed_out = threading.Event()

            def terminate_on_timeout():
                timed_out.set()
                try:
                    process.kill()
                except ProcessLookupError:
                    pass

            timer = threading.Timer(self.timeout, terminate_on_timeout)
            timer.start()
            pending = ""
            response = ""
            started = False
            markers = ("assistant<|end_header_id|>",)

            def clean_ready(value: str, final: bool = False) -> str:
                if "PyTorchObserver" in value:
                    value = value.split("PyTorchObserver", 1)[0]
                    final = True
                safe_length = len(value) if final else max(0, len(value) - 32)
                safe = value[:safe_length]
                safe = _LOG_RX.sub("", safe)
                safe = re.sub(r"<\|.*?\|>", "", safe)
                return safe

            try:
                while True:
                    char = process.stdout.read(1)
                    if not char:
                        break
                    if not started:
                        pending += char
                        prompt_at = pending.find(prompt)
                        marker_at = max((pending.find(marker) for marker in markers), default=-1)
                        if prompt_at >= 0:
                            pending = pending[prompt_at + len(prompt):]
                            started = True
                        elif marker_at >= 0:
                            marker = markers[0]
                            pending = pending[marker_at + len(marker):]
                            started = True
                        elif len(pending) >= 32 and not pending.startswith("<"):
                            started = True
                        else:
                            continue
                        response += pending
                        pending = ""
                    else:
                        response += char

                    if len(response) >= 44:
                        safe = clean_ready(response)
                        response = response[-32:]
                        if safe:
                            yield safe

                return_code = process.wait()
                timer.cancel()
                if timed_out.is_set():
                    raise subprocess.TimeoutExpired(self._command(prompt), self.timeout)
                if return_code:
                    raise RuntimeError(f"llama_main exited with status {return_code}")
                if not started:
                    response = pending
                tail = clean_ready(response, final=True)
                if tail:
                    yield tail
            finally:
                timer.cancel()
                if process.poll() is None:
                    process.kill()
                    process.wait()
                process.stdout.close()

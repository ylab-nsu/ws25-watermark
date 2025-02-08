# Watermark RISC-V

Watermark RISC-V

Python приложение, позволяющее кодировать сообщения в elf файлах собранных под risc-v

Использует библиотеку capstone для работы

### Как использовать

```
git clone https://github.com/ylab-nsu/ws25-watermark
cd ws25-watermark
pip3 install -e .
```

Чтобы закодировать

```
riscv-watermark -e *строка* -m *метод* файл
```

Чтобы раскодировать

```
riscv-watermark -d -m *метод* файл.patched
```

Перед попытками что-то зашить рекомендуется воспользоваться флагом -g,``riscv-watermark -g -m *метод* файл`` чтобы узнать, сколько бит вообще данная версия программы способная закодировать конкретным методом (на текущий момент 08.02.25 программа кодирует только текстовые собщения, но кодирование конкретного набора бит тоже будет имплементироавнно в рамках решения другой задачи)

### Принцип работы

Выполняется замена ассемблерных инструкций на функционально эквивалентные путём изменения бинарного кода исполняемого файла.
Группы функционально эквивалентных функций:

1. addi dst, src, 0; add dst, src, zero
2. c.nop; c.or x8, x8; c.andi x8, 0b011111; c.sub x8, x8

На данный момент имеется только один рабочий модуль, который опирается на замену инструкций на функционально эквивалентные, чтобы кодировать сообщение в файл. Другой модуль будет менять заданные компилятором размеры стек фреймов для кодирования, что, конечно, будет минусом, поскольку будет уходить больше памяти (огромные количества в крайних случая), но в замен даст возможноть закодировать гораздо больше информации

Замены на функционально эквивалентные функции в контексте целой программы не вносят заметных изменений в скорость исполнения

![image](https://i.imgur.com/QVnxOlj.png)

Python tool to encode messages in risc-v compiled elf files

Requires capstone library to work (although it is possible to make it work without Capstone, but only with one module)

At the moment we have only one module up and working, this module relies on functionaly equal assembler instructions to encode message inside the binary (would be much easier to implement on CISC architecture), the other module would tweak compiler's given sizes for stackframes in order to encode message, which, of course comes with the tradeoff of memory (large amounts in some edge cases), but in turn should give much bigger amount of different combinations (e.g. unique binaries)

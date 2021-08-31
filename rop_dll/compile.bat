cl /c rop_main.c
nasm -f win64 rop.asm
link /DLL /OUT:rop.dll rop_main.obj rop.obj

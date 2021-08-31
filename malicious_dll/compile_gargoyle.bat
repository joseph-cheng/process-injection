cl /c malicious.c reflective_loader.c
nasm -f win64 gargoyle.asm
link /DLL /OUT:gargoyle.dll malicious.obj reflective_loader.obj gargoyle.obj


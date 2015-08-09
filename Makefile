CFLAGS := -Iinclude -DIF_LOG
OUT_PATH := out/lib/
OBJ_FILE := handler.o looper.o msg_queue.o
LIB_FILE := libmsg_handler

all : $(LIB_FILE)

$(OUT_PATH)%.o : %.c
	gcc $(CFLAGS) -Wall -fPIC -c $^ -o $@

$(LIB_FILE) : $(addprefix $(OUT_PATH), $(OBJ_FILE))
	gcc $(CFLAGS) -shared -Wl,-soname,$@.so $^ -lpthread -o $(OUT_PATH)$@.so

clean :
	rm $(OUT_PATH)$(LIB_FILE).so $(addprefix $(OUT_PATH), $(OBJ_FILE))

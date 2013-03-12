CC ?= gcc

TARGETS = \
		  utc_SecurityFW_ssm_write_file_func	\
		  utc_SecurityFW_ssm_write_buffer_func	\
		  utc_SecurityFW_ssm_read_func	\
		  utc_SecurityFW_ssm_getinfo_func	\
		  utc_SecurityFW_ssm_delete_file_func

PKGS = secure-storage

LDFLAGS = `pkg-config --libs $(PKGS)`
LDFLAGS += $(TET_ROOT)/lib/tet3/tcm_s.o
LDFLAGS += -L$(TET_ROOT)/lib/tet3 -ltcm_s
LDFLAGS += -L$(TET_ROOT)/lib/tet3 -lapi_s

CFLAGS = -I. `pkg-config --cflags $(PKGS)`
CFLAGS += -I$(TET_ROOT)/inc/tet3
CFLAGS += -Wall

all: $(TARGETS)

$(TARGETS): %: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(TARGETS) *~

package=sodium
$(package)_version=1.0.18
$(package)_download_path=https://download.libsodium.org/libsodium/releases/
$(package)_file_name=libsodium-$($(package)_version).tar.gz
$(package)_sha256_hash=6f504490b342a4f8a4c4a02fc9b866cbef8622d5df4e5452b46be121e46636c1
$(package)_patches=disable-glibc-getrandom-getentropy.patch fix-whitespace.patch

define $(package)_set_vars
$(package)_config_opts=--enable-static --disable-shared --with-pic="yes"
$(package)_config_opts+=--prefix=$(host_prefix)
$(package)_config_opts_darwin=RANLIB="$($(package)_ranlib)" AR="$($(package)_ar)" CC="$($(package)_cc)"
endef

define $(package)_config_cmds
  patch -p1 < $($(package)_patch_dir)/disable-glibc-getrandom-getentropy.patch &&\
  ./autogen.sh &&\
  patch -p1 < $($(package)_patch_dir)/fix-whitespace.patch &&\
  $($(package)_autoconf) $($(package)_config_opts)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm lib/*.la
endef

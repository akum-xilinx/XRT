add_subdirectory(include)

set(XRT_KERNEL_HEADERS
  include/xocl_ioctl.h
  include/xocl_kernel_api.h
)


install(FILES ${XRT_KERNEL_HEADERS} DESTINATION ${XRT_INSTALL_DIR}/include/kernel)

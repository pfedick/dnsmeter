dnl AC_CHECK_PCRE2([ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])

AC_DEFUN([AC_CHECK_PCRE2],[
AC_MSG_CHECKING(if we should use pcre2)

AC_ARG_WITH([pcre2],
	[  --with-pcre2[[=PATH]]     Prefix where libpcre2 is installed (optional)],
	[libpcre2_prefix="$withval"],
	[libpcre2_prefix="auto"])

	if test "$libpcre2_prefix" != "no"
	then
		AC_MSG_RESULT(yes)
		am_save_CFLAGS="$CFLAGS"
		am_save_CPPFLAGS="$CPPFLAGS"
		am_save_LIBS="$LIBS"
		am_save_LDFLAGS="$LDFLAGS"


		if test "$libpcre2_prefix" = "yes" -o "$libpcre2_prefix" = "auto"
		then
			AC_PATH_PROG(pcre2config,pcre2-config)
			PKG_CHECK_MODULES([PCRE2_8], [libpcre2-8],
				have_libpcre2="yes"
				PCRE2_LIBS="$PCRE2_8_LIBS"
				PCRE2_CFLAGS="$PCRE2_8_CFLAGS"
				AC_DEFINE(HAVE_PCRE2_BITS_8)
				,
				have_libpcre2="no"
				PCRE2_LIBS=""
				PCRE2_CFLAGS=""

				if test [ -x "$pcre2config" ]
				then
					have_libpcre2="yes"
					PCRE2_LIBS=`$pcre2config --libs8`
					PCRE2_CFLAGS=`$pcre2config --cflags`
					AC_DEFINE(HAVE_PCRE2_BITS_8)
				fi
			)
			if test ${ac_cv_sizeof_wchar_t} -eq 2
			then
				PKG_CHECK_MODULES([PCRE2_WIDE16], [libpcre2-16],
					PCRE2_LIBS="$PCRE2_LIBS $PCRE2_WIDE16_LIBS"
					PCRE2_CFLAGS="$PCRE2_CFLAGS $PCRE2_WIDE16_CFLAGS"
					AC_DEFINE(HAVE_PCRE2_BITS_16)
					,

					if test [ -x "$pcre2config" ]
					then
						have_libpcre2="yes"
						libs16=`$pcre2config --libs16`
						PCRE2_LIBS="$PCRE2_LIBS $libs16"
						AC_DEFINE(HAVE_PCRE2_BITS_16)
					fi
				)
			fi
			if test ${ac_cv_sizeof_wchar_t} -eq 4
			then
				PKG_CHECK_MODULES([PCRE2_WIDE32], [libpcre2-32],
					PCRE2_LIBS="$PCRE2_LIBS $PCRE2_WIDE32_LIBS"
					PCRE2_CFLAGS="$PCRE2_CFLAGS $PCRE2_WIDE32_CFLAGS"
					AC_DEFINE(HAVE_PCRE2_BITS_32)
					,
					if test [ -x "$pcre2config" ]
					then
						have_libpcre2="yes"
						libs32=`$pcre2config --libs32`
						PCRE2_LIBS="$PCRE2_LIBS $libs32"
						AC_DEFINE(HAVE_PCRE2_BITS_32)
					fi

				)
			fi
		else
			LIBS="-L$libpng_prefix/lib"
			CFLAGS="-I$libpng_prefix/include"
			CPPFLAGS="-I$libpng_prefix/include"
			LDFLAGS="-L$libpng_prefix/lib"
			PCRE2_LIBS="-L$libpcre2_prefix/lib -lpcre2-8"
			PCRE2_CFLAGS="-I$libpcre2_prefix/include"
			AC_DEFINE(HAVE_PCRE2_BITS_8)
		fi


		LIBS="$am_save_LIBS"
		LDFLAGS="$am_save_LDFLAGS"
		CFLAGS="$am_save_CFLAGS"
		CPPFLAGS="$am_save_CPPFLAGS"
	else
		AC_MSG_RESULT(no)
	fi
	if test $have_libpcre2 = "yes"
	then
		#echo "PCRE2_LIBS=$PCRE2_LIBS"
		AC_SUBST(PCRE2_LIBS)
		AC_SUBST(PCRE2_CFLAGS)

		ifelse([$1], , :, [$1])
	else
		PCRE2_LIBS=""
		PCRE2_CFLAGS=""
		ifelse([$2], , :, [$2])
	fi

])

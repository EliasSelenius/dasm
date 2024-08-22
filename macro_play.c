
char* time = __TIME__;
char* date = __DATE__;
int stdc = __STDC__;


/*
num_args(a, b, c)
num_args_(a, b, c, 9,8,7,6,5,4,3,2,1,0)
arg_n(a, b, c, 9,8,7,6,5,4,3,2,1,0)
3
*/

#define num_args(...) num_args_(__VA_ARGS__, seq_n)
#define num_args_(...) arg_n(__VA_ARGS__)
#define arg_n(_1, _2, _3, _4, _5, _6, _7, _8, _9, N, ...) N
#define seq_n 9,8,7,6,5,4,3,2,1,0


#define empty()
#define defer(id) id empty()
#define expand(...) __VA_ARGS__
#define expandmore(...) expand(expand(expand(expand(expand(expand(expand(expand(__VA_ARGS__))))))))

#define concat(a, ...) a ## __VA_ARGS__

#define inc_0 1
#define inc_1 2
#define inc_2 3
#define inc_3 4
#define inc_4 5
#define inc_5 6
#define inc_6 7
#define inc_7 8

#define inc(n) concat(inc_, n)
int inc_test = inc(inc(inc(1)));



#define forever() ? defer(forever_ind)()()
#define forever_ind() forever

expand(forever())
expand(expand(forever()))
expandmore(forever())

#define repeat_0(X)
#define repeat_1(X) X
#define repeat_2(X) X X
#define repeat_3(X) X X X

#define repeat(X, ...) concat(repeat_, num_args(__VA_ARGS__))(X)
repeat(foo, a,  g)

#define index_0(n, ...) n
#define index_1(_0, n, ...) n
#define index_2(_0, _1, n, ...) n
#define index_3(_0, _1, _2, n, ...) n
#define index_4(_0, _1, _2, _3, n, ...) n
#define index(n, ...) index_##n(__VA_ARGS__)
index(0, a, b, c, d)
index(1, a, b, c, d)
index(2, a, b, c, d)
index(3, a, b, c, d)
index(4, a, b, c, d)


#define par(item) (item)
#define apply(item0, ...) par(item0) defer(apply_ind)()(__VA_ARGS__)
#define apply_ind() apply
expandmore(apply(a, b, c, d, e, f))
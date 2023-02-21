function diag_mat = fft_diag_matrix(n, l, t) 
    p = 3221225473; % 3 * 2^30 + 1;
    g = 2550486681; % generator of the prime field p
    w = mod(g^3, p);
    v = zeros(1, 2^l);
    for i=1:2^l
        v(i) = mod(sym(w)^(partial_bit_reversal(n, l+1, t+i-1)), p);
    end
    diag_mat = diag(v);
end


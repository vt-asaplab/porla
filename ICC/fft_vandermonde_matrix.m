function vand_fft_mat = fft_vandermonde_matrix(n, l) 
    p = 3221225473; % 3 * 2^30 + 1;
    g = 2550486681;
    w = mod(g^3, p);
%     disp(w);
    v = zeros(1, 2^l);
    for i=1:2^l
        v(i) = mod(sym(w)^(2*n/(2^l)*2^(i-1)), p);
    end
    vand_fft_mat = vander(v);
    vand_fft_mat = mod(vand_fft_mat, p);
end
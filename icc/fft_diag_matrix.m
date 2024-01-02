function diag_mat = fft_diag_matrix(n, l, t) 
    k = floor(log2(n));
    p = 257;            % 2 * (2 * 64) + 1;
    g = 3;              % generator of the Z_p*
    w = mod(g^2, p);    % 2n-th primitive root of unity mod p
    v = zeros(1, 2^l);
    for i = 1:2^l
        v(i) = mod(sym(w)^(partial_bit_reversal(k+1, k-l, t+i-1)), p);
    end
    diag_mat = diag(v);
end


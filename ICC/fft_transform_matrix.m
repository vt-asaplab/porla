function vand_fft_mat = fft_transform_matrix(n, l) 
    p = 257;            % 2 * (2 * 64) + 1;
    g = 3;              % generator of the Z_p*
    w = mod(g^2, p);    % 2n-th primitive root of unity mod p
    v = zeros(1, 2^l);
    for i = 1:2^l
        v(i) = mod((sym(w)^(n/(2^l)))^(i-1), p);
    end
    vand_fft_mat = vander(v);
    vand_fft_mat = mod(vand_fft_mat, p);
end
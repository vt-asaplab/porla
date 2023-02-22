clear; clc;

% Number of data blocks
n = 2^6;
% Level
l = 4;
% Time
t = 1;

% FFT Vandermonde matrix
F_l  = fft_transform_matrix(n, l);

% Diagonal matrix 
D_lt = fft_diag_matrix(n, l, t);

% Generator matrix
G    = [F_l, D_lt * F_l];

% Original data
data = randi([1 100], 1, 2^l);
disp('Data: ');
disp(data);

% Hierarchical log at level l
H_l  = data * G;

% Suppose that 2^l positions have been corrupted 
% And other 2^l positions are good
H_l_hat = H_l;
G_l_hat = G;

H_size = length(H_l_hat); 

for i = 1:2^l
    % Choose a random column as corrupted column to be removed
    j = randi(H_size);
    
    % Remove column j in Hierarchical Log H
    H_l_hat(:,j) = [];
    
    % Remove column j in Generator G
    G_l_hat(:, j) = [];
    
    % Decrease size due to the removed column
    H_size = H_size - 1;
end

% Recover data by using only 2^l arbitrary columns
recovered_data = int32(H_l_hat * inv(G_l_hat));

% Display recovered data
disp('Recovered Data: ');
disp(recovered_data);
